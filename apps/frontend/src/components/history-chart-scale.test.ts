import { describe, expect, it } from "vitest";
import { getAutomaticHistoryChartScale } from "./history-chart-scale";

describe("getAutomaticHistoryChartScale", () => {
  it("returns a safe empty domain when there are no finite values", () => {
    expect(getAutomaticHistoryChartScale([])).toEqual({
      scale: "linear",
      domain: [0, 1],
      showNetContribution: false,
    });
  });

  it("keeps linear scale for short periods", () => {
    const scale = getAutomaticHistoryChartScale([
      { totalValue: 100, netContribution: 100 },
      { totalValue: 1500, netContribution: 1200 },
    ]);

    expect(scale.scale).toBe("linear");
    expect(scale.showNetContribution).toBe(true);
    expect(scale.domain[0]).toBe(0);
    expect(scale.domain[1]).toBeCloseTo(1725);
  });

  it("keeps linear scale when total value includes zero or negative values", () => {
    const scale = getAutomaticHistoryChartScale([
      { totalValue: 100, netContribution: 100 },
      { totalValue: 0, netContribution: 100 },
      { totalValue: 1500, netContribution: 1200 },
    ]);

    expect(scale.scale).toBe("linear");
    expect(scale.showNetContribution).toBe(true);
    expect(scale.domain[0]).toBe(0);
    expect(scale.domain[1]).toBeCloseTo(1725);
  });

  it("keeps linear scale when the visible value range is narrow", () => {
    const scale = getAutomaticHistoryChartScale([
      { totalValue: 1700, netContribution: 1690 },
      { totalValue: 1750, netContribution: 1720 },
      { totalValue: 1800, netContribution: 1740 },
    ]);

    expect(scale.scale).toBe("linear");
    expect(scale.showNetContribution).toBe(true);
    expect(scale.domain[0]).toBeCloseTo(1685);
    expect(scale.domain[1]).toBeCloseTo(1815);
  });

  it("anchors material positive ranges to zero for visual context", () => {
    const scale = getAutomaticHistoryChartScale([
      { totalValue: 2000, netContribution: 0 },
      { totalValue: 1500, netContribution: 0 },
      { totalValue: 2000, netContribution: 0 },
    ]);

    expect(scale.scale).toBe("linear");
    expect(scale.showNetContribution).toBe(true);
    expect(scale.domain).toEqual([0, 2300]);
  });

  it("fits visible values without zero anchoring when requested", () => {
    const scale = getAutomaticHistoryChartScale(
      [
        { totalValue: 2000, netContribution: 0 },
        { totalValue: 1500, netContribution: 0 },
        { totalValue: 2000, netContribution: 0 },
      ],
      { mode: "fit-visible" },
    );

    expect(scale.scale).toBe("linear");
    expect(scale.showNetContribution).toBe(false);
    expect(scale.domain[0]).toBeCloseTo(1425);
    expect(scale.domain[1]).toBeCloseTo(2020);
  });

  it("biases fit-visible padding below the data to reduce empty headroom", () => {
    const scale = getAutomaticHistoryChartScale(
      [
        { totalValue: 1500, netContribution: 0 },
        { totalValue: 2000, netContribution: 0 },
      ],
      { mode: "fit-visible" },
    );

    expect(1500 - scale.domain[0]).toBeGreaterThan(scale.domain[1] - 2000);
  });

  it("keeps fit-visible periods calmer when a minimum domain span ratio is provided", () => {
    const scale = getAutomaticHistoryChartScale(
      [
        { totalValue: 90, netContribution: 0 },
        { totalValue: 100, netContribution: 0 },
      ],
      { mode: "fit-visible", minDomainSpanRatio: 0.2 },
    );

    expect(scale.scale).toBe("linear");
    expect(scale.domain[1] - scale.domain[0]).toBeCloseTo(19);
  });

  it("expands fit-visible scale to show net contribution when the span stays reasonable", () => {
    const scale = getAutomaticHistoryChartScale(
      [
        { totalValue: 650_000, netContribution: 531_202.07 },
        { totalValue: 706_926.56, netContribution: 531_202.07 },
        { totalValue: 690_000, netContribution: 531_202.07 },
      ],
      { mode: "fit-visible", netContributionMaxDomainSpanRatio: 5 },
    );

    expect(scale.scale).toBe("linear");
    expect(scale.showNetContribution).toBe(true);
    expect(scale.domain[0]).toBeLessThan(531_202.07);
    expect(scale.domain[1]).toBeGreaterThan(706_926.56);
  });

  it("keeps net contribution hidden when including it would flatten fit-visible data", () => {
    const scale = getAutomaticHistoryChartScale(
      [
        { totalValue: 700_000, netContribution: 531_202.07 },
        { totalValue: 706_926.56, netContribution: 531_202.07 },
        { totalValue: 704_000, netContribution: 531_202.07 },
      ],
      { mode: "fit-visible", netContributionMaxDomainSpanRatio: 5 },
    );

    expect(scale.scale).toBe("linear");
    expect(scale.showNetContribution).toBe(false);
    expect(scale.domain[0]).toBeGreaterThan(531_202.07);
  });

  it("keeps high-value low-volatility periods readable", () => {
    const scale = getAutomaticHistoryChartScale([
      { totalValue: 1_021_150, netContribution: 1_000_000 },
      { totalValue: 1_021_210, netContribution: 1_000_000 },
      { totalValue: 1_021_195, netContribution: 1_000_000 },
    ]);

    expect(scale.scale).toBe("linear");
    expect(scale.showNetContribution).toBe(false);
    expect(scale.domain[1] - scale.domain[0]).toBeCloseTo(102.1185);
  });

  it("preserves real deposit jumps instead of forcing log scale", () => {
    const scale = getAutomaticHistoryChartScale([
      { totalValue: 43_000, netContribution: 43_000 },
      { totalValue: 43_600, netContribution: 43_000 },
      { totalValue: 143_000, netContribution: 143_000 },
    ]);

    expect(scale.scale).toBe("linear");
    expect(scale.showNetContribution).toBe(true);
    expect(scale.domain[0]).toBe(0);
    expect(scale.domain[1]).toBeCloseTo(164_450);
  });

  it("anchors material negative ranges to zero for visual context", () => {
    const scale = getAutomaticHistoryChartScale([
      { totalValue: -2000, netContribution: -1800 },
      { totalValue: -1500, netContribution: -1600 },
      { totalValue: -2000, netContribution: -1700 },
    ]);

    expect(scale.scale).toBe("linear");
    expect(scale.showNetContribution).toBe(true);
    expect(scale.domain[0]).toBeCloseTo(-2300);
    expect(scale.domain[1]).toBe(0);
  });

  it("keeps a valid domain for zero balances", () => {
    const scale = getAutomaticHistoryChartScale([
      { totalValue: 0, netContribution: 0 },
      { totalValue: 0, netContribution: 0 },
      { totalValue: 0, netContribution: 0 },
    ]);

    expect(scale.scale).toBe("linear");
    expect(scale.showNetContribution).toBe(true);
    expect(scale.domain).toEqual([0, 0.01]);
  });

  it("keeps sub-dollar balances readable", () => {
    const scale = getAutomaticHistoryChartScale([
      { totalValue: 0.1, netContribution: 0.1 },
      { totalValue: 0.12, netContribution: 0.1 },
      { totalValue: 0.11, netContribution: 0.1 },
    ]);

    expect(scale.scale).toBe("linear");
    expect(scale.showNetContribution).toBe(true);
    expect(scale.domain[0]).toBeCloseTo(0.097);
    expect(scale.domain[1]).toBeCloseTo(0.123);
  });

  it("uses log scale for positive periods spanning at least one order of magnitude", () => {
    const scale = getAutomaticHistoryChartScale([
      { totalValue: 100, netContribution: 100 },
      { totalValue: 1000, netContribution: 900 },
      { totalValue: 1500, netContribution: 1100 },
    ]);

    expect(scale.scale).toBe("log");
    expect(scale.showNetContribution).toBe(true);
    expect(scale.domain[0]).toBeCloseTo(95);
    expect(scale.domain[1]).toBeCloseTo(1575);
  });

  it("hides net contribution in log scale when it would make the axis invalid", () => {
    const scale = getAutomaticHistoryChartScale([
      { totalValue: 100, netContribution: 0 },
      { totalValue: 1500, netContribution: 1000 },
      { totalValue: 2000, netContribution: -100 },
    ]);

    expect(scale.scale).toBe("log");
    expect(scale.showNetContribution).toBe(false);
    expect(scale.domain[0]).toBeCloseTo(95);
    expect(scale.domain[1]).toBeCloseTo(2100);
  });
});
