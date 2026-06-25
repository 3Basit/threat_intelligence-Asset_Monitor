# Model Card: VCDB-FAIR Cyber Risk Magnitude Model

## Model Details

| Field | Value |
|-------|-------|
| **Name** | VCDB-FAIR Cyber Risk Magnitude Model |
| **Version** | 1.1 |
| **Type** | ElasticNet (scikit-learn) — L1+L2 regularized linear model |
| **Framework** | FAIR (Factor Analysis of Information Risk) |
| **Target Variable** | `log1p(total_incident_cost_usd)` — log-transformed actual financial loss |
| **Training Data** | 288 real-world incidents from VCDB (Verizon Community Database), filtered from 10,037 total (only 3.2% had usable loss data) |
| **Features** | 23 total — 5 numeric engineered + 18 one-hot encoded from 2 categoricals (`industry_sector`, `attack_type`) |
| **License** | Research / Internal Use |
| **Date** | 2026 |

## Performance Metrics

| Metric | Value | Notes |
|--------|-------|-------|
| R² (TimeSeriesSplit, k=5) | 0.1903 | Time-honest: train on older, test on newer incidents |
| Fold Mean R² ± Std | 0.168 ± 0.150 | Positive and stable — honest generalization |
| Median Absolute Error | ~$404K | Dollar-space |
| MAE (log-space) | 2.08 | Log-space absolute error |
| Cross-Validation | TimeSeriesSplit(n_splits=5) | Prevents temporal leakage |
| Conformal Coverage | 81.2% | Target: 80% (CV+ method) |
| Conformal Interval Width | 6.42 log-units | ~×150 uncertainty range |
| Training Samples | 288 | VCDB labeled incidents only |

> **Note on evaluation methodology:** TimeSeriesSplit replaces random KFold — data is sorted by `incident_year` and each fold trains on past incidents only to prevent temporal leakage. The resulting R²=0.1903 is honest (vs 0.204 with random KFold). ElasticNet was selected over RandomForest, Ridge, XGBoost, and LightGBM. Its L1+L2 regularization automatically zeros out 15 of 23 features, keeping only the most informative ones.

> **Note on data expansion experiments (v1.1):** Infrastructure exists for SEC EDGAR 8-K Item 1.05 and Ransomwhere.today data sources. SEC EDGAR currently uses IBM benchmark costs as placeholders (needs NLP for real cost extraction). Ransomwhere degrades the global model due to distribution mismatch ($6M median vs $232K VCDB median). Both sources are preserved for future work.

> **Note on feature change (v1.1):** `ibm_industry_benchmark_log` was removed after SHAP showed 0% importance (ElasticNet L1 zeroed it out). `incident_year_normalized` was added to capture breach cost inflation (~10%/year). The IBM benchmark is still used via Bühlmann credibility blending post-prediction.

## Top Features (Importance)

| Rank | Feature | Coef. Importance | SHAP Importance |
|------|---------|-----------------|------------------|
| 1 | `log_records_affected` | 20.3% | 45.1% |
| 2 | `log_records_cost` | 12.7% | 40.8% |
| 3 | `attack_type_social` | 19.8% | 1.9% |
| 4 | `data_sensitivity_score` | 13.3% | 4.2% |
| 5 | `attack_type_hacking` | 10.7% | 2.2% |

> **Note:** ElasticNet's L1 regularization zeroed out 15 of 23 features, selecting only the 8 most informative. This automatic feature selection improves generalization on small datasets.

## Intended Use

**Primary use case:** Order-of-magnitude cyber risk estimation for vulnerability prioritization.

**Intended users:**
- Security teams performing risk-based vulnerability management
- Risk managers conducting FAIR-based quantitative risk assessments
- Cyber insurance analysts estimating loss exposure

**Out-of-scope uses (NOT intended for):**
- Precise actuarial pricing
- Regulatory compliance calculations
- Legal liability estimation

## Limitations

1. **Small training set.** Only 288 incidents have reported financial losses. Many industries have fewer than 20 training samples, limiting per-industry reliability.
2. **Partial cost data.** VCDB records fines and settlements from public sources — not full breach costs (which IBM/Ponemon methodology measures). This means the model captures a subset of total economic impact.
3. **US-dominated.** Approximately 80% of training data originates from US-based incidents. Regional effects are applied externally via IBM Cost of Data Breach multipliers rather than learned from VCDB data.
4. **Prediction variance.** Individual predictions can vary widely. Use prediction intervals (80% CI provided) rather than point estimates alone.
5. **Temporal trend captured but limited.** `incident_year_normalized` captures the historical inflation trend in VCDB data (2010–present), but predictions may still underestimate costs for future incidents if breach costs continue rising faster than historical trends.

## Ethical Considerations

- **Predictions should inform, not replace, expert risk assessment.** Model outputs are one input to a broader decision-making process and should be contextualized by domain expertise.
- **Over-reliance on point estimates could lead to under-investment in security** for industries with few VCDB samples, where model confidence is inherently low.
- **The credibility weighting mechanism (Bühlmann) explicitly addresses sparse-data bias** by falling back to industry benchmarks when per-industry training samples are insufficient, preventing the model from making overconfident predictions in low-data regimes.

## Production Enhancements (v1.1)

### Credibility Weighting
Bühlmann credibility theory blends ML predictions with IBM Cost of Data Breach benchmarks. The blending weight is determined by per-industry sample count: industries with more VCDB training data receive higher weight on the ML prediction, while data-sparse industries fall back toward the IBM benchmark.

### Prediction Intervals
Conformal prediction using CV+ (Cross-Validation Plus, cv=5) via MAPIE provides distribution-free 80% confidence intervals. CV+ was selected over Jackknife+ for tighter intervals (6.42 vs 6.43 in log-space) at the same coverage level (81.2%). Both methods are evaluated automatically during training and the tighter one is selected. Each output includes a `confidence_tier` (high/medium/low) based on Bühlmann Z.

### SHAP Explainability
LinearExplainer provides per-prediction feature attribution, enabling users to understand which risk factors drive each individual cost estimate.

To retrain the production model:
```bash
python -m prediction_model.model_training --compare
```

## Data Sources

| Source | Role |
|--------|------|
| VCDB (Verizon Community Database) | Primary training data — real incident costs |
| IBM Cost of Data Breach Report 2025 | Industry/region benchmarks (Ponemon methodology) |
| Verizon DBIR 2025 | Base breach rates by industry |
| CISA KEV (Known Exploited Vulnerabilities) | Exploit status (frequency side of FAIR) |
| NVD / EPSS | Vulnerability scoring (frequency side of FAIR) |

## References

- Bühlmann, H. (1967). *Experience Rating and Credibility.* ASTIN Bulletin, 4(3), 199–207.
- Hubbard, D. & Seiersen, R. (2016). *How to Measure Anything in Cybersecurity Risk.* Wiley.
- Freund, J. & Jones, J. (2014). *Measuring and Managing Information Risk: A FAIR Approach.* Butterworth-Heinemann.
