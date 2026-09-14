"""
SentinelFlow Data Cleaning Pipeline (scripts/clean_data.py)

Cleans raw and normalized tabular flow datasets:
1. Replaces +/- infinity with NaN
2. Drops rows with all NaN values or corrupted records
3. Converts numeric columns safely with error coercion
4. Performs controlled zero/median imputations for missing values
5. Removes uninformative exact duplicate flows while preserving temporal integrity
"""
from __future__ import annotations

from pathlib import Path
from typing import Tuple

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
NORMALIZED_DIR = PROJECT_ROOT / "data" / "processed" / "normalized"
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"


def clean_numeric_data(
    df: pd.DataFrame,
    fill_missing_value: float = 0.0,
    drop_all_nan_rows: bool = True,
) -> pd.DataFrame:
    """
    Cleans DataFrame numeric data:
    - Replaces +/- np.inf with np.nan
    - Drops empty rows
    - Coerces numerical columns to float64
    - Fills remaining NaN values with fill_missing_value
    """
    cleaned = df.copy()

    # 1. Replace infinities with NaN
    cleaned = cleaned.replace([np.inf, -np.inf], np.nan)

    # 2. Drop rows where all elements are NaN
    if drop_all_nan_rows:
        cleaned = cleaned.dropna(axis=0, how="all")

    # 3. Numeric conversions for continuous features
    for col in cleaned.columns:
        if col not in ("timestamp", "flow_id", "src_ip", "dst_ip", "protocol", "threat_class", "label"):
            cleaned[col] = pd.to_numeric(cleaned[col], errors="coerce").fillna(fill_missing_value)

    return cleaned


def deduplicate_flows(df: pd.DataFrame, subset_cols: list[str] | None = None) -> Tuple[pd.DataFrame, int]:
    """
    Removes exact duplicate flow entries if present.
    Returns the deduplicated DataFrame and the count of dropped duplicates.
    """
    initial_count = len(df)
    deduped = df.drop_duplicates(subset=subset_cols)
    dropped = initial_count - len(deduped)
    return deduped, dropped


def clean_dataset_file(input_file: Path, output_file: Path | None = None) -> pd.DataFrame:
    """Loads, cleans, deduplicates, and optionally saves the cleaned dataset."""
    df = pd.read_csv(input_file)
    print(f"[*] Cleaning {input_file.name} (Initial rows: {len(df)})")

    # Clean numerics
    df_cleaned = clean_numeric_data(df)

    # Deduplicate
    df_cleaned, dropped_dups = deduplicate_flows(df_cleaned)
    if dropped_dups > 0:
        print(f"    -> Removed {dropped_dups} duplicate flow records")

    if output_file:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        df_cleaned.to_csv(output_file, index=False)
        print(f"    -> Saved cleaned dataset to {output_file} ({len(df_cleaned)} rows)")

    return df_cleaned


if __name__ == "__main__":
    print("=== SentinelFlow Data Cleaning Pipeline ===")
    
    # Process normalized directory if files exist
    if NORMALIZED_DIR.exists():
        for csv_file in NORMALIZED_DIR.glob("*.csv"):
            cleaned = clean_dataset_file(csv_file)
            print(f"Processed {csv_file.name}: {len(cleaned)} clean rows, {len(cleaned.columns)} columns.")
