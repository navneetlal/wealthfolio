const LOG_SCALE_MIN_POINTS = 3;
const LOG_SCALE_MIN_RATIO = 10;
const LINEAR_DOMAIN_PADDING_RATIO = 0.15;
const FIT_VISIBLE_UPPER_PADDING_RATIO = 0.04;
const LINEAR_ZERO_ANCHOR_RANGE_RATIO = 0.2;
const LINEAR_MIN_VISIBLE_SPAN_RATIO = 0.0001;
const LINEAR_MIN_VISIBLE_SPAN = 0.01;

export type HistoryChartScale = "linear" | "log";
export type HistoryChartScaleMode = "automatic" | "fit-visible";

export interface HistoryChartScaleDataPoint {
  totalValue: number;
  netContribution: number;
}

export interface HistoryChartScaleOptions {
  mode?: HistoryChartScaleMode;
  netContributionMaxDomainSpanRatio?: number;
  minDomainSpanRatio?: number;
}

export interface HistoryChartScaleConfig {
  scale: HistoryChartScale;
  domain: [number, number];
  showNetContribution: boolean;
}

function getLinearDomain(
  values: number[],
  anchorMaterialRangesToZero = true,
  minDomainSpanRatio = LINEAR_MIN_VISIBLE_SPAN_RATIO,
  upperPaddingRatio = LINEAR_DOMAIN_PADDING_RATIO,
): [number, number] {
  const minValue = Math.min(...values);
  const maxValue = Math.max(...values);
  const range = maxValue - minValue;
  const maxMagnitude = Math.max(Math.abs(minValue), Math.abs(maxValue));
  const relativeRange = maxMagnitude > 0 ? range / maxMagnitude : 0;

  if (anchorMaterialRangesToZero && relativeRange >= LINEAR_ZERO_ANCHOR_RANGE_RATIO) {
    if (minValue >= 0) {
      return [0, Math.max(maxValue * (1 + LINEAR_DOMAIN_PADDING_RATIO), LINEAR_MIN_VISIBLE_SPAN)];
    }

    if (maxValue <= 0) {
      return [Math.min(minValue * (1 + LINEAR_DOMAIN_PADDING_RATIO), -LINEAR_MIN_VISIBLE_SPAN), 0];
    }
  }

  const minVisibleSpan = Math.max(
    Math.abs((minValue + maxValue) / 2) * minDomainSpanRatio,
    LINEAR_MIN_VISIBLE_SPAN,
  );
  const span = Math.max(
    range * (1 + LINEAR_DOMAIN_PADDING_RATIO + upperPaddingRatio),
    minVisibleSpan,
  );
  const extraSpan = span - range;
  const totalPaddingRatio = LINEAR_DOMAIN_PADDING_RATIO + upperPaddingRatio;
  let lower = minValue - extraSpan * (LINEAR_DOMAIN_PADDING_RATIO / totalPaddingRatio);
  let upper = maxValue + extraSpan * (upperPaddingRatio / totalPaddingRatio);

  if (minValue >= 0 && lower < 0) {
    lower = 0;
    upper = span;
  }

  return [lower, upper];
}

function containsAllValues(domain: [number, number], values: number[]) {
  const [lower, upper] = domain;
  return values.every((value) => Number.isFinite(value) && value >= lower && value <= upper);
}

function domainSpan(domain: [number, number]) {
  return domain[1] - domain[0];
}

export function getAutomaticHistoryChartScale(
  data: HistoryChartScaleDataPoint[],
  options: HistoryChartScaleOptions = {},
): HistoryChartScaleConfig {
  const totalValues = data.map((item) => item.totalValue).filter(Number.isFinite);

  if (totalValues.length === 0) {
    return { scale: "linear", domain: [0, 1], showNetContribution: false };
  }

  const mode = options.mode ?? "automatic";
  const upperPaddingRatio =
    mode === "fit-visible" ? FIT_VISIBLE_UPPER_PADDING_RATIO : LINEAR_DOMAIN_PADDING_RATIO;
  let linearDomain = getLinearDomain(
    totalValues,
    mode === "automatic",
    options.minDomainSpanRatio,
    upperPaddingRatio,
  );
  const netContributionValues = data.map((item) => item.netContribution);
  let showNetContributionInLinearScale = containsAllValues(linearDomain, netContributionValues);

  if (
    !showNetContributionInLinearScale &&
    options.netContributionMaxDomainSpanRatio &&
    netContributionValues.every(Number.isFinite)
  ) {
    const combinedValues = [...totalValues, ...netContributionValues];
    const combinedDomain = getLinearDomain(
      combinedValues,
      mode === "automatic",
      options.minDomainSpanRatio,
      upperPaddingRatio,
    );
    const maxSpan = domainSpan(linearDomain) * options.netContributionMaxDomainSpanRatio;

    if (
      containsAllValues(combinedDomain, netContributionValues) &&
      domainSpan(combinedDomain) <= maxSpan
    ) {
      linearDomain = combinedDomain;
      showNetContributionInLinearScale = true;
    }
  }

  if (mode === "fit-visible") {
    return {
      scale: "linear",
      domain: linearDomain,
      showNetContribution: showNetContributionInLinearScale,
    };
  }

  if (totalValues.length < LOG_SCALE_MIN_POINTS) {
    return {
      scale: "linear",
      domain: linearDomain,
      showNetContribution: showNetContributionInLinearScale,
    };
  }

  if (totalValues.some((value) => value <= 0)) {
    return {
      scale: "linear",
      domain: linearDomain,
      showNetContribution: showNetContributionInLinearScale,
    };
  }

  const minTotalValue = Math.min(...totalValues);
  const maxTotalValue = Math.max(...totalValues);

  if (maxTotalValue / minTotalValue < LOG_SCALE_MIN_RATIO) {
    return {
      scale: "linear",
      domain: linearDomain,
      showNetContribution: showNetContributionInLinearScale,
    };
  }

  const logDomain: [number, number] = [minTotalValue * 0.95, maxTotalValue * 1.05];
  const showNetContribution = netContributionValues.every(
    (value) =>
      Number.isFinite(value) && value > 0 && value >= logDomain[0] && value <= logDomain[1],
  );

  return {
    scale: "log",
    domain: logDomain,
    showNetContribution,
  };
}
