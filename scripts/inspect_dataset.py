from pathlib import Path

import pandas as pd


DATA_DIR = Path(
    "data/processed/normalized"
)


for file in DATA_DIR.glob("*.csv"):
    df = pd.read_csv(file)

    print("\nFILE:", file.name)
    print("Rows:", len(df))
    print("Columns:", len(df.columns))

    print("\nColumns:")
    print(df.columns.tolist())

    print("\nLabels:")
    print(
        df.iloc[:, -1]
        .value_counts()
        .head(20)
    )
