export type View = 'overview' | 'analysis' | 'history' | 'evidence' | 'system'

export type EvidenceScenario = {
  scenario: string
  rows?: number
  row_f1?: number
  row_recall?: number
  clean_row_fpr?: number
  attack_episodes?: number
  detected_attack_episodes?: number
  false_alarm_episodes?: number
  invalid_rows?: number
  attack_phase_breakdown?: Record<string, { labeled_rows: number; review_rows: number; row_recall: number }>
}

export type ResearchEvidence = {
  status: string
  dataset: string
  evidence_date: string
  records: (EvidenceScenario | { study: string } | { scenario: string })[]
}

export type ProtocolResearch = {
  status: string
  scope: string
  records: {
    scenario: string
    physics: { f1: number; recall: number; clean_fpr: number }
    unexpected_modbus_writer: { f1: number; recall: number; clean_fpr: number }
    two_lane_or: { f1: number; recall: number; clean_fpr: number }
    unexpected_write_count: number
  }[]
  limitations: string[]
}

export type ProtocolSensitivity = {
  status: string
  hold_seconds: number
  warning: string
  records: {scenario: string;tp: number;fp: number;fn: number;clean_row_fpr: number}[]
}

export type FourLaneResearch = {
  status: string
  dataset: string
  macro_f1: number
  ablation: Record<string, {
    macro_f1_without_lane: number
    exclusive_attack_rows_across_S1_S6: number
    exclusive_benign_alert_rows_across_S1_S6: number
  }>
  warning: string
  records: Array<{
    scenario: string
    physics: { f1: number; clean_fpr: number }
    modbus_source_hold5: { f1: number; clean_fpr: number }
    arp_claim_hold2: { f1: number; clean_fpr: number }
    price_domain: { f1: number; clean_fpr: number }
    four_lane_or: { f1: number; clean_fpr: number; fp: number }
    clean_alert_episodes: { episodes: number; alert_seconds: number }
    false_alert_temporal_attribution?: {
      false_alert_rows_total: number
      within_5_seconds: number
      between_5_and_30_seconds: number
      farther_than_30_seconds: number
      far_clean_rows: number
      far_clean_alert_rows: number
      far_clean_alert_rate: number | null
    }
  }>
}

export type PriceContextResearch = {
  status: string
  full_or_macro_f1: number
  security_only_macro_f1: number
  price_exclusive_attack_rows_not_security_alerted: number
  price_exclusive_benign_alert_rows_not_security_alerted: number
  price_lane_treatment: string
  scenarios: Array<{scenario: string; full_or_f1: number; security_only_f1: number; price_only_attack_review_rows: number; price_only_benign_review_rows: number}>
  benign_price_offset_stress: Array<{additive_shift_eur_per_kwh: number; observed_benign_seconds: number; false_review_seconds: number; benign_false_review_fraction: number}>
  warning: string
}

export type ARPResearch = {
  status: string
  warning: string
  records: Array<{
    scenario: string
    physics: { f1: number; clean_fpr: number }
    arp_source_consistency: { f1: number; clean_fpr: number }
    two_lane_or: { f1: number; clean_fpr: number }
    per_phase: Record<string, { labeled_rows: number; physics_alert_rows: number; arp_alert_rows: number; or_alert_rows: number }>
  }>
  hold5_sensitivity: Array<{
    scenario: string
    two_lane_or: { f1: number; clean_fpr: number }
  }>
  policy_sweep: Array<{
    scenario: string
    arp_hold_seconds: number
    combined: { f1: number; clean_fpr: number; fp: number }
    clean_alert_burden: { episodes: number; alert_seconds: number; longest_episode_seconds: number }
    per_phase: Record<string, { labeled_seconds: number; or_detected_seconds: number }>
    status: string
  }>
  negative_controls: Array<{
    scenario: string
    arp_hold_seconds: number
    arp_packets_observed: number
    known_ip_mac_mismatch_packets: number
    total_seconds: number
    clean_seconds: number
    arp_alert_seconds_total: number
    clean_row_alert_rate: number
    status: string
  }>
  uncertainty: {
    status: string
    confidence: number
    observed_clean_seconds: number
    observed_arp_packets: number
    observed_scenarios: number
    hypothetical_iid_per_second_upper_rate: number
    hypothetical_iid_per_packet_upper_mismatch_rate: number
    hypothetical_independent_scenario_upper_event_probability: number
    warnings: string[]
  }
  identity_ambiguity: {
    status: string
    sample_seconds: number
    change_window_seconds: number
    records: Array<{
      hold_seconds: number
      synthetic_maintenance_false_alert_seconds: number
      synthetic_spoof_attack_detected_seconds: number
      synthetic_attack_labeled_seconds: number
      identical_arp_observations: boolean
    }>
    conclusion: string
    requirement: string
    warning: string
  }
}

export type Finding = {
  id: string
  timestamp: string
  kind: 'LOCAL_PHYSICS_REVIEW' | 'ABSTAIN'
  score: number | null
  identity_name: string | null
  reason?: string | null
  analysis_id?: string
}

export type Analysis = {
  id: string
  created_at: string
  source_name: string
  observation_count: number
  review_count: number
  abstention_count: number
  max_score: number
  duration_seconds: number
  model_id: string
  findings?: Finding[]
}

export type Overview = {
  model_status: string
  analyses: number
  observations: number
  review_rows: number
  abstention_rows: number
  last_analysis_at: string | null
  daily_activity: { date: string; runs: number; reviews: number; observations: number }[]
  recent_findings: Finding[]
}

export type ModelInfo = {
  model_id: string
  status: string
  features: number
  feature_names: string[]
  required_devices: string[]
  required_fields: string[]
  confirmation_rows: number
  training_rows: number
  calibration_rows: number
  source_sha256: string
  limitations: string[]
}

export type Readiness = {
  status: string
  database: string
  model_id: string
}

export type MeasurementRecord = {
  timestamp: string
  values: Record<string, number | null>
}
