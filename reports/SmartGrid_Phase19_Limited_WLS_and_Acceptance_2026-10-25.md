# Smart Grid Co-Pilot — Phase 19: Limited Constrained WLS and Objective Completion Gate

25 October 2026. Research-only. No paper written. This report builds on Phases 16–18 and deliberately records a model failure.

## Implementation

Implemented a **linear, three-constraint weighted projection** for the separate COCOON `pv_2_3` network using nine measured active-power channels, the two feeder sum constraints and the upstream POI sum. The estimator solves

\[
 \widehat z = z - R C^T(CRC^T)^{-1} C z,
\]

where `C` is a rank-3 conservation incidence matrix and `R` is a diagonal measurement uncertainty matrix derived from the publisher's per-measurement `std_2.json`. The calculation projects the measurement vector onto the three equality constraints, yielding a weighted residual and measurement-correction magnitudes.

**Boundary:** This is *not* complete nonlinear AC bus-voltage WLS, robust Huber fitting, a true LNR bad-data-removal iteration or authenticated attack attribution. Line impedances, reactive power, currents and state variables are not yet included in a physically verified AC measurement function. The publisher has not verified for us whether `std_2` entries are variances or standard deviations, so we tested **both interpretations**.

## Results on 100 held-out clean `pf100pos` snapshots

Calibration: 100 separate `pf090pos` clean cases (99th-percentile score threshold), while the 100 `pf090neg` cases were for inspection. Attack injection trials altered each of nine P channels across 100 heldout operating points; only trials with unflagged paired clean control qualify for additional detection.

| Uncertainty interpretation | Unmodified clean false alerts | 20% synthetic single-channel attack recall, conditional on unflagged paired clean | Correct top-1 source location among detected |
|---|---:|---:|---:|
| Treat `std_2` as **variance** | **13/100** | **526/783 = 67.18%** | **53.99%** |
| Treat `std_2` as **standard deviation**, square for variance | **25/100** | **675/675 = 100%** | **38.07%** |

Both models yield near-zero post-projection conservation error, proving the **numerical projection** works. It does **not** prove the original observed readings were attacks or that corrected channels correspond to the manipulated sensor: the projection redistributes differences among physically coupled meters. Higher synthetic sensitivity in the second interpretation accompanies unacceptably high clean false alarms and worse localization.

The three feeder equalities were correct mathematical inputs for a limited estimator, but its **learned, cross-power-factor threshold is not transportable**. The Phase18 separate **fixed-tolerance** head was more stable for isolated mathematical manipulations, yet itself was exploratory/post hoc and blind to perfectly conservation-preserving coordinated attacks. Neither is acceptable as a field IDS without additional independent physical/provenance evidence.

## Completion and quality gate

Added a read-only one-command `smartgrid_research_acceptance.py` script. It runs the reserved Data4Cyber S1-alt test, S6 observability audit, strict physics detector, COCOON PV topology balance benchmark, this constrained projection and publisher smart-attack reaggregation. **All six code/reproducibility checks pass**.

The same gate evaluates ten explicitly chosen research-readiness requirements. **Three pass; seven are blocked/failed**, including:

- Poor Modbus generalization on a reserved real attack run.
- Missing authenticated preattack MQTT price baseline and publication packets.
- No sealed unseen MITM site/test campaign confirming the excellent S4 result.
- Missing publisher-verified per-row COCOON PHIL HIL attack windows/network model and meter covariance.
- No independently demonstrated protected anchor, low multi-site benign false-alarm rate, or validated full AC WLS.

The gate is intentionally conservative and not a numerical estimate of the remaining time; **3/10 must never be presented as “30% completed”**. Research prototype engineering remains substantial (approximately 75–80% by judgment), but reaching scientifically defensible 100% cannot be certified with the current evidence.

## What is now genuinely needed from outside this dataset collection

1. Independent labeled MITM captures that preserve per-phase and three-phase aggregate power channels, from a new session/testbed, before further test-facing architecture changes.
2. COCOON author-supplied network model/impedance/units and true attack start/stop logs for energy-community PHIL, not just `FDD.json` detector outputs.
3. Signed/verified original price feed or broker publication evidence for MQTT S6; its released tap has no malicious MQTT packet evidence.
4. Confirmed `std_2` uncertainty units/semantics and suitable electrical solver model validation, to implement a valid nonlinear AC WLS/LNR method.
5. Longer independent clean baseline from multiple regimes/sites to set a prospective false-alarm budget.

**Do not imply 100% completion by relabeling experiments, inventing absent ground truth, or optimizing thresholds on held-out outcomes.** No paper written.

## Reproduce

Download the Data4Cyber v3 and COCOON `pv_2_3` public research ZIPs into the same directory as the code, using names in prior reports. Then run:

```bash
python3 -B cocoon_pv23_constrained_wls.py --variance-mode as_variance
python3 -B cocoon_pv23_constrained_wls.py --variance-mode as_std
python3 -B smartgrid_research_acceptance.py
python3 -B smartgrid_research_acceptance.py --strict
```

`--strict` exits nonzero while research-readiness gates fail, even if every experiment reproduces. That is intentional, not a software defect.
