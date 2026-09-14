# Dataset Architecture

## 1. Objective

SentinelFlow uses a combination of public datasets and
authorized lab-generated traffic for training and evaluation.

## 2. Data Sources

### Public datasets

- CIC-IDS2017
- CIC-DDoS2019
- CTU-13

### Lab-generated traffic

- iperf3
- Ostinato
- TRex
- hping3
- DNS tunnelling traffic
- DGA-generated domains
- C2 beacon emulator

## 3. Data Flow

```text
Public datasets + Lab traffic
        ↓
Normalization
        ↓
Common feature schema
        ↓
Train / Validation / Test
        ↓
Detection Engine
```

## 4. Dataset Splitting

Training, validation and test data are separated by
traffic runs/sessions where possible.

The test set is kept unseen during model training.

## 5. Data Privacy

Raw PCAPs and large datasets are not committed to GitHub.

Only small representative sample data is included.

## 6. Security Constraints

Traffic generation is performed only in an authorized,
isolated laboratory environment.

SentinelFlow operates on passive observations and does not
perform active probing, blocking or mitigation.
