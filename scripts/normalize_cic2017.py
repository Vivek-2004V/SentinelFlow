from pathlib import Path

import pandas as pd


INPUT_DIR = Path("data/raw/public/cic_ids2017")
OUTPUT_DIR = Path("data/processed/normalized")

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def clean_column_names(
    dataframe: pd.DataFrame,
) -> pd.DataFrame:
    dataframe.columns = (
        dataframe.columns
        .str.strip()
        .str.lower()
        .str.replace(" ", "_")
        .str.replace("/", "_")
    )

    return dataframe


def normalize_file(
    input_path: Path,
) -> pd.DataFrame:

    df = pd.read_csv(input_path)

    df = clean_column_names(df)

    return df


if __name__ == "__main__":
    for file in INPUT_DIR.glob("*.csv"):
        print(f"Processing: {file.name}")

        dataframe = normalize_file(file)

        output_path = (
            OUTPUT_DIR / f"{file.stem}_normalized.csv"
        )

        dataframe.to_csv(
            output_path,
            index=False,
        )

        print(f"Saved: {output_path}")
