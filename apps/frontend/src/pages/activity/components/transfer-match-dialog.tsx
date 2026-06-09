import { useCallback, useEffect, useMemo, useState } from "react";

import {
  findTransferMatchCandidates,
  getTransferPairForActivity,
  searchActivities,
} from "@/adapters";
import { ActivityStatus, ActivityType, ActivityTypeNames } from "@/lib/constants";
import type { Account, Activity, ActivityDetails, TransferMatchCandidate } from "@/lib/types";
import { cn, formatDateISO, formatDateTime } from "@/lib/utils";
import {
  Badge,
  Button,
  formatAmount,
  Icons,
  Input,
  ScrollArea,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from "@wealthfolio/ui";
import { useActivityMutations } from "../hooks/use-activity-mutations";

export type TransferDialogActivity = Activity | ActivityDetails;

interface SelectedCandidate {
  activity: TransferDialogActivity;
  reasons: string[];
  warnings: string[];
}

interface TransferMatchDialogProps {
  open: boolean;
  mode: "link" | "unlink";
  sourceActivity?: TransferDialogActivity | null;
  accounts: Account[];
  onOpenChange: (open: boolean) => void;
  onComplete?: () => void | Promise<unknown>;
}

interface NormalizedTransferActivity {
  id: string;
  accountId: string;
  accountName: string;
  accountType: string;
  accountCurrency: string;
  activityType: string;
  date: Date | string;
  amount?: string | null;
  quantity?: string | null;
  unitPrice?: string | null;
  currency: string;
  assetId?: string;
  assetSymbol?: string;
  notes?: string;
  sourceGroupId?: string;
  status?: string;
}

const ALL = "__all__";
const STRICT = "strict";
const ANY = "any";
const SAME_ASSET = "same";
const CASH_ASSET = "cash";

function isTransferType(activityType: string | undefined): boolean {
  return activityType === ActivityType.TRANSFER_IN || activityType === ActivityType.TRANSFER_OUT;
}

function oppositeTransferType(activityType: string | undefined): ActivityType | undefined {
  if (activityType === ActivityType.TRANSFER_IN) return ActivityType.TRANSFER_OUT;
  if (activityType === ActivityType.TRANSFER_OUT) return ActivityType.TRANSFER_IN;
  return undefined;
}

function parseNumber(value: string | number | null | undefined): number | undefined {
  if (value == null) return undefined;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function absEquals(a: number | undefined, b: number | undefined, tolerance = 0.000001): boolean {
  if (a == null || b == null) return false;
  return Math.abs(Math.abs(a) - Math.abs(b)) <= tolerance;
}

function getActivityDate(activity: TransferDialogActivity): Date | string {
  return "date" in activity ? activity.date : activity.activityDate;
}

function getActivityNotes(activity: TransferDialogActivity): string | undefined {
  if ("comment" in activity) return activity.comment;
  return (activity as Activity).notes;
}

function getActivityAssetSymbol(activity: TransferDialogActivity): string | undefined {
  if ("assetSymbol" in activity && activity.assetSymbol?.trim()) return activity.assetSymbol;
  return activity.assetId;
}

function getAccountName(
  activity: TransferDialogActivity,
  accountMap: Map<string, Account>,
): string {
  if ("accountName" in activity && activity.accountName?.trim()) return activity.accountName;
  return accountMap.get(activity.accountId)?.name ?? activity.accountId;
}

function getAccountCurrency(
  activity: TransferDialogActivity,
  accountMap: Map<string, Account>,
): string {
  if ("accountCurrency" in activity && activity.accountCurrency?.trim()) {
    return activity.accountCurrency;
  }
  return accountMap.get(activity.accountId)?.currency ?? activity.currency;
}

function normalizeActivity(
  activity: TransferDialogActivity,
  accountMap: Map<string, Account>,
): NormalizedTransferActivity {
  const account = accountMap.get(activity.accountId);
  return {
    id: activity.id,
    accountId: activity.accountId,
    accountName: getAccountName(activity, accountMap),
    accountType: account?.accountType ?? "",
    accountCurrency: getAccountCurrency(activity, accountMap),
    activityType: activity.activityType,
    date: getActivityDate(activity),
    amount: activity.amount,
    quantity: activity.quantity,
    unitPrice: activity.unitPrice,
    currency: activity.currency,
    assetId: activity.assetId,
    assetSymbol: getActivityAssetSymbol(activity),
    notes: getActivityNotes(activity),
    sourceGroupId: activity.sourceGroupId,
    status: activity.status,
  };
}

function assetKey(activity: NormalizedTransferActivity): string | undefined {
  const raw = (activity.assetId ?? activity.assetSymbol ?? "").trim();
  if (!raw) return undefined;
  const key = raw.toUpperCase();
  if (key === "CASH" || key.startsWith("$CASH") || key.startsWith("CASH:")) return undefined;
  return key;
}

function amountValue(activity: NormalizedTransferActivity): number | undefined {
  const amount = parseNumber(activity.amount);
  if (amount != null) return amount;
  const quantity = parseNumber(activity.quantity);
  const unitPrice = parseNumber(activity.unitPrice);
  if (quantity != null && unitPrice != null) return quantity * unitPrice;
  return undefined;
}

function isSecurityTransfer(activity: NormalizedTransferActivity): boolean {
  return Boolean(assetKey(activity));
}

function sameExactShape(
  source: NormalizedTransferActivity,
  candidate: NormalizedTransferActivity,
): boolean {
  if (isSecurityTransfer(source) || isSecurityTransfer(candidate)) {
    return (
      assetKey(source) === assetKey(candidate) &&
      absEquals(parseNumber(source.quantity), parseNumber(candidate.quantity))
    );
  }
  return (
    source.currency === candidate.currency && absEquals(amountValue(source), amountValue(candidate))
  );
}

function canLinkCandidate(
  source: NormalizedTransferActivity,
  candidate: NormalizedTransferActivity,
): boolean {
  if (isSecurityTransfer(source) || isSecurityTransfer(candidate)) {
    return (
      assetKey(source) === assetKey(candidate) &&
      absEquals(parseNumber(source.quantity), parseNumber(candidate.quantity))
    );
  }
  return true;
}

function dateDiffDays(a: Date | string, b: Date | string): number | undefined {
  const left = new Date(a).getTime();
  const right = new Date(b).getTime();
  if (!Number.isFinite(left) || !Number.isFinite(right)) return undefined;
  return Math.round(Math.abs(left - right) / (1000 * 60 * 60 * 24));
}

function dateWindow(date: Date | string, windowDays: number): { from: string; to: string } {
  const center = new Date(date);
  const from = new Date(center);
  const to = new Date(center);
  from.setDate(center.getDate() - windowDays);
  to.setDate(center.getDate() + windowDays);
  return { from: formatDateISO(from), to: formatDateISO(to) };
}

function activityMatchesText(activity: NormalizedTransferActivity, searchText: string): boolean {
  const needle = searchText.trim().toLowerCase();
  if (!needle) return true;
  const haystack = [activity.notes, activity.assetSymbol, activity.assetId, activity.accountName]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
  return haystack.includes(needle);
}

function manualWarnings(
  source: NormalizedTransferActivity,
  candidate: NormalizedTransferActivity,
): string[] {
  const warnings: string[] = [];
  const diff = dateDiffDays(source.date, candidate.date);
  if (diff && diff > 0) warnings.push(`Dates differ by ${diff} day${diff === 1 ? "" : "s"}.`);
  if (source.currency !== candidate.currency) {
    warnings.push(`Currencies differ (${source.currency} / ${candidate.currency}).`);
  }
  const sourcePrice = parseNumber(source.unitPrice);
  const candidatePrice = parseNumber(candidate.unitPrice);
  if (
    sourcePrice != null &&
    candidatePrice != null &&
    !absEquals(sourcePrice, candidatePrice, 0.01)
  ) {
    warnings.push("Prices differ.");
  }
  if (!sameExactShape(source, candidate)) {
    warnings.push("Amount or quantity does not exactly match.");
  }
  return warnings;
}

function activitySortKey(activity: TransferDialogActivity): string {
  return `${new Date(getActivityDate(activity)).getTime()}-${activity.id}`;
}

function ActivitySummaryRow({
  activity,
  accountMap,
  label,
}: {
  activity: TransferDialogActivity;
  accountMap: Map<string, Account>;
  label?: string;
}) {
  const normalized = normalizeActivity(activity, accountMap);
  const date = formatDateTime(normalized.date).date;
  const amount = amountValue(normalized);
  const quantity = parseNumber(normalized.quantity);
  const symbol = normalized.assetSymbol || normalized.assetId || "Cash";
  const typeName =
    ActivityTypeNames[normalized.activityType as ActivityType] ?? normalized.activityType;

  return (
    <div className="bg-muted/30 flex flex-col gap-1 rounded-md border px-3 py-2 text-sm">
      <div className="text-muted-foreground flex items-center justify-between gap-3 text-xs uppercase">
        <span>{label ?? typeName}</span>
        <span>{date}</span>
      </div>
      <div className="flex items-center justify-between gap-3">
        <span className="min-w-0 truncate font-medium">{normalized.accountName}</span>
        <span className="shrink-0">
          {amount != null
            ? formatAmount(Math.abs(amount), normalized.currency)
            : normalized.currency}
        </span>
      </div>
      <div className="text-muted-foreground flex items-center justify-between gap-3 text-xs">
        <span className="min-w-0 truncate">{normalized.notes || symbol}</span>
        <span className="shrink-0">
          {quantity != null ? `${Math.abs(quantity)} ${symbol}` : normalized.accountCurrency}
        </span>
      </div>
    </div>
  );
}

function CandidateButton({
  candidate,
  accountMap,
  selected,
  onSelect,
}: {
  candidate: SelectedCandidate;
  accountMap: Map<string, Account>;
  selected: boolean;
  onSelect: () => void;
}) {
  return (
    <button
      type="button"
      className={cn(
        "hover:bg-muted/50 w-full rounded-md border p-2 text-left transition-colors",
        selected && "border-primary bg-primary/5",
      )}
      onClick={onSelect}
    >
      <ActivitySummaryRow activity={candidate.activity} accountMap={accountMap} />
      {candidate.reasons.length > 0 ? (
        <div className="text-muted-foreground mt-2 flex flex-wrap gap-1 text-[11px]">
          {candidate.reasons.map((reason) => (
            <Badge key={reason} variant="secondary" className="rounded-sm px-1.5 py-0">
              {reason}
            </Badge>
          ))}
        </div>
      ) : null}
      {candidate.warnings.length > 0 ? (
        <div className="mt-2 flex items-start gap-1.5 text-[11px] text-amber-600">
          <Icons.AlertTriangle className="mt-0.5 h-3 w-3 shrink-0" />
          <span>{candidate.warnings.join(" ")}</span>
        </div>
      ) : null}
    </button>
  );
}

export function TransferMatchDialog({
  open,
  mode,
  sourceActivity,
  accounts,
  onOpenChange,
  onComplete,
}: TransferMatchDialogProps) {
  const accountMap = useMemo(
    () => new Map(accounts.map((account) => [account.id, account])),
    [accounts],
  );
  const activeAccounts = useMemo(
    () => accounts.filter((account) => !account.isArchived),
    [accounts],
  );
  const accountTypeOptions = useMemo(
    () => Array.from(new Set(activeAccounts.map((account) => account.accountType))).sort(),
    [activeAccounts],
  );
  const currencyOptions = useMemo(
    () => Array.from(new Set(activeAccounts.map((account) => account.currency))).sort(),
    [activeAccounts],
  );

  const source = useMemo(
    () => (sourceActivity ? normalizeActivity(sourceActivity, accountMap) : null),
    [accountMap, sourceActivity],
  );
  const oppositeType = oppositeTransferType(source?.activityType);

  const { linkTransferActivitiesMutation, unlinkTransferActivitiesMutation } =
    useActivityMutations();
  const isProcessing =
    mode === "link"
      ? linkTransferActivitiesMutation.isPending
      : unlinkTransferActivitiesMutation.isPending;

  const [suggestions, setSuggestions] = useState<TransferMatchCandidate[]>([]);
  const [suggestionsLoading, setSuggestionsLoading] = useState(false);
  const [suggestionsError, setSuggestionsError] = useState<string | null>(null);
  const [manualResults, setManualResults] = useState<ActivityDetails[]>([]);
  const [manualSearched, setManualSearched] = useState(false);
  const [manualLoading, setManualLoading] = useState(false);
  const [manualError, setManualError] = useState<string | null>(null);
  const [selectedCandidate, setSelectedCandidate] = useState<SelectedCandidate | null>(null);
  const [counterpart, setCounterpart] = useState<TransferDialogActivity | null>(null);
  const [counterpartError, setCounterpartError] = useState<string | null>(null);
  const [counterpartLoading, setCounterpartLoading] = useState(false);

  const [searchText, setSearchText] = useState("");
  const [accountId, setAccountId] = useState(ALL);
  const [accountType, setAccountType] = useState(ALL);
  const [windowDays, setWindowDays] = useState("7");
  const [currency, setCurrency] = useState(ALL);
  const [assetFilter, setAssetFilter] = useState(ALL);
  const [matchMode, setMatchMode] = useState(STRICT);

  const resetFilters = useCallback(() => {
    setSearchText("");
    setAccountId(ALL);
    setAccountType(ALL);
    setWindowDays("7");
    setCurrency(ALL);
    setAssetFilter(ALL);
    setMatchMode(STRICT);
    setManualResults([]);
    setManualSearched(false);
    setManualError(null);
  }, []);

  useEffect(() => {
    if (!open) return;
    setSelectedCandidate(null);
    setSuggestions([]);
    setSuggestionsError(null);
    setManualResults([]);
    setManualSearched(false);
    setManualError(null);
    setCounterpart(null);
    setCounterpartError(null);

    if (!sourceActivity?.id) return;

    if (mode === "link") {
      setSuggestionsLoading(true);
      findTransferMatchCandidates({ activityId: sourceActivity.id, windowDays: 7, limit: 25 })
        .then((result) => setSuggestions(result))
        .catch((error) =>
          setSuggestionsError(
            error instanceof Error ? error.message : "Could not load suggested matches.",
          ),
        )
        .finally(() => setSuggestionsLoading(false));
    } else {
      setCounterpartLoading(true);
      getTransferPairForActivity(sourceActivity.id)
        .then((pair) => {
          setCounterpart(
            sourceActivity.id === pair.transferIn.id ? pair.transferOut : pair.transferIn,
          );
        })
        .catch((error) =>
          setCounterpartError(
            error instanceof Error ? error.message : "Could not load the linked transfer pair.",
          ),
        )
        .finally(() => setCounterpartLoading(false));
    }
  }, [mode, open, sourceActivity]);

  const suggestedCandidates = useMemo<SelectedCandidate[]>(
    () =>
      suggestions.map((candidate) => ({
        activity: candidate.activity,
        reasons: candidate.reasons,
        warnings: candidate.warnings,
      })),
    [suggestions],
  );

  const filteredManualResults = useMemo<SelectedCandidate[]>(() => {
    if (!source || !oppositeType) return [];
    return manualResults
      .filter((activity) => {
        const candidate = normalizeActivity(activity, accountMap);
        const candidateAccount = accountMap.get(candidate.accountId);
        if (candidate.id === source.id) return false;
        if (candidate.accountId === source.accountId) return false;
        if (candidate.sourceGroupId) return false;
        if (candidate.activityType !== oppositeType) return false;
        if (candidate.status && candidate.status !== ActivityStatus.POSTED) return false;
        if (accountId !== ALL && candidate.accountId !== accountId) return false;
        if (accountType !== ALL && candidateAccount?.accountType !== accountType) return false;
        if (currency !== ALL && candidate.currency !== currency) return false;
        if (assetFilter === SAME_ASSET && assetKey(candidate) !== assetKey(source)) return false;
        if (assetFilter === CASH_ASSET && assetKey(candidate)) return false;
        if (!canLinkCandidate(source, candidate)) return false;
        if (matchMode === STRICT && !sameExactShape(source, candidate)) return false;
        return activityMatchesText(candidate, searchText);
      })
      .sort((left, right) => activitySortKey(right).localeCompare(activitySortKey(left)))
      .map((activity) => {
        const candidate = normalizeActivity(activity, accountMap);
        const reasons = sameExactShape(source, candidate)
          ? [isSecurityTransfer(source) ? "Same asset and quantity" : "Same amount and currency"]
          : ["Eligible opposite transfer"];
        return {
          activity,
          reasons,
          warnings: manualWarnings(source, candidate),
        };
      });
  }, [
    accountId,
    accountMap,
    accountType,
    assetFilter,
    currency,
    manualResults,
    matchMode,
    oppositeType,
    searchText,
    source,
  ]);

  const runManualSearch = useCallback(async () => {
    if (!source || !oppositeType) return;
    const days = Number(windowDays);
    const safeWindowDays = Number.isFinite(days) ? days : 7;
    const { from, to } = dateWindow(source.date, safeWindowDays);
    setManualLoading(true);
    setManualError(null);
    try {
      const response = await searchActivities(
        0,
        250,
        {
          activityTypes: [oppositeType],
          accountIds: accountId === ALL ? undefined : [accountId],
          dateFrom: from,
          dateTo: to,
        },
        "",
        { id: "date", desc: true },
      );
      setManualResults(response.data);
      setManualSearched(true);
    } catch (error) {
      setManualError(error instanceof Error ? error.message : "Could not search activities.");
    } finally {
      setManualLoading(false);
    }
  }, [accountId, oppositeType, source, windowDays]);

  const confirmLink = useCallback(async () => {
    if (!sourceActivity?.id || !selectedCandidate?.activity.id) return;
    await linkTransferActivitiesMutation.mutateAsync({
      activityAId: sourceActivity.id,
      activityBId: selectedCandidate.activity.id,
    });
    await onComplete?.();
    onOpenChange(false);
  }, [
    linkTransferActivitiesMutation,
    onComplete,
    onOpenChange,
    selectedCandidate?.activity.id,
    sourceActivity?.id,
  ]);

  const confirmUnlink = useCallback(async () => {
    if (!sourceActivity?.id || !counterpart?.id) return;
    await unlinkTransferActivitiesMutation.mutateAsync({
      activityAId: sourceActivity.id,
      activityBId: counterpart.id,
    });
    await onComplete?.();
    onOpenChange(false);
  }, [
    counterpart?.id,
    onComplete,
    onOpenChange,
    sourceActivity?.id,
    unlinkTransferActivitiesMutation,
  ]);

  const title = mode === "link" ? "Link transfer" : "Unlink transfer";
  const description =
    mode === "link"
      ? "Choose the existing opposite transfer to pair with this activity."
      : "This transfer pair will be split back into two external transfers.";

  if (!sourceActivity || !source || !isTransferType(source.activityType)) {
    return null;
  }

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent className="flex w-full flex-col overflow-hidden sm:max-w-[760px]">
        <SheetHeader>
          <SheetTitle>{title}</SheetTitle>
          <SheetDescription>{description}</SheetDescription>
        </SheetHeader>

        <div className="min-h-0 flex-1 space-y-4 overflow-y-auto py-4">
          <div className="space-y-2">
            <div className="text-muted-foreground text-xs font-medium uppercase">Selected row</div>
            <ActivitySummaryRow activity={sourceActivity} accountMap={accountMap} />
          </div>

          {mode === "unlink" ? (
            <div className="space-y-3">
              <div className="text-muted-foreground text-xs font-medium uppercase">
                Linked counterpart
              </div>
              {counterpartLoading ? (
                <div className="text-muted-foreground rounded-md border p-3 text-sm">
                  Loading linked transfer...
                </div>
              ) : counterpart ? (
                <ActivitySummaryRow activity={counterpart} accountMap={accountMap} />
              ) : (
                <div className="text-destructive rounded-md border p-3 text-sm">
                  {counterpartError ?? "No valid linked counterpart found."}
                </div>
              )}
            </div>
          ) : (
            <>
              <div className="space-y-2">
                <div className="flex items-center justify-between gap-2">
                  <div className="text-muted-foreground text-xs font-medium uppercase">
                    Suggested matches
                  </div>
                  <Badge variant="outline" className="rounded-sm">
                    {oppositeType
                      ? (ActivityTypeNames[oppositeType] ?? oppositeType)
                      : "Opposite transfer"}
                  </Badge>
                </div>
                {suggestionsLoading ? (
                  <div className="text-muted-foreground rounded-md border p-3 text-sm">
                    Loading suggestions...
                  </div>
                ) : suggestionsError ? (
                  <div className="text-destructive rounded-md border p-3 text-sm">
                    {suggestionsError}
                  </div>
                ) : suggestedCandidates.length > 0 ? (
                  <div className="space-y-2">
                    {suggestedCandidates.map((candidate) => (
                      <CandidateButton
                        key={candidate.activity.id}
                        candidate={candidate}
                        accountMap={accountMap}
                        selected={selectedCandidate?.activity.id === candidate.activity.id}
                        onSelect={() => setSelectedCandidate(candidate)}
                      />
                    ))}
                  </div>
                ) : (
                  <div className="text-muted-foreground rounded-md border p-3 text-sm">
                    No suggested matches in the default 7-day window.
                  </div>
                )}
              </div>

              <div className="space-y-3 rounded-md border p-3">
                <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                  <div className="min-w-0">
                    <div className="text-sm font-medium">Search eligible transfers</div>
                    <div className="text-muted-foreground text-xs">
                      Opposite transfer type is locked; filters narrow the candidate list.
                    </div>
                  </div>
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    className="w-full sm:w-auto"
                    onClick={resetFilters}
                  >
                    Reset filters
                  </Button>
                </div>

                <div className="grid grid-cols-1 gap-2 md:grid-cols-3">
                  <div className="md:col-span-2">
                    <Input
                      value={searchText}
                      onChange={(event) => setSearchText(event.target.value)}
                      placeholder="Search notes, symbol, account"
                    />
                  </div>
                  <Input
                    value={
                      oppositeType
                        ? (ActivityTypeNames[oppositeType] ?? oppositeType)
                        : "Opposite transfer"
                    }
                    readOnly
                    aria-label="Locked opposite transfer type"
                  />

                  <Select value={accountId} onValueChange={setAccountId}>
                    <SelectTrigger>
                      <SelectValue placeholder="Account" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value={ALL}>All accounts</SelectItem>
                      {activeAccounts.map((account) => (
                        <SelectItem key={account.id} value={account.id}>
                          {account.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>

                  <Select value={accountType} onValueChange={setAccountType}>
                    <SelectTrigger>
                      <SelectValue placeholder="Account type" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value={ALL}>All account types</SelectItem>
                      {accountTypeOptions.map((type) => (
                        <SelectItem key={type} value={type}>
                          {type}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>

                  <Select value={windowDays} onValueChange={setWindowDays}>
                    <SelectTrigger>
                      <SelectValue placeholder="Date range" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="7">Within 7 days</SelectItem>
                      <SelectItem value="30">Within 30 days</SelectItem>
                      <SelectItem value="90">Within 90 days</SelectItem>
                      <SelectItem value="180">Within 180 days</SelectItem>
                    </SelectContent>
                  </Select>

                  <Select value={currency} onValueChange={setCurrency}>
                    <SelectTrigger>
                      <SelectValue placeholder="Currency" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value={ALL}>All currencies</SelectItem>
                      {currencyOptions.map((option) => (
                        <SelectItem key={option} value={option}>
                          {option}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>

                  <Select value={assetFilter} onValueChange={setAssetFilter}>
                    <SelectTrigger>
                      <SelectValue placeholder="Asset" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value={ALL}>All assets</SelectItem>
                      {isSecurityTransfer(source) ? (
                        <SelectItem value={SAME_ASSET}>Same asset</SelectItem>
                      ) : (
                        <SelectItem value={CASH_ASSET}>Cash only</SelectItem>
                      )}
                    </SelectContent>
                  </Select>

                  <Select value={matchMode} onValueChange={setMatchMode}>
                    <SelectTrigger>
                      <SelectValue placeholder="Match mode" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value={STRICT}>Exact amount/quantity</SelectItem>
                      <SelectItem value={ANY}>Any eligible transfer</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="flex items-center justify-between gap-2">
                  <div className="text-muted-foreground text-xs">
                    Search scans up to 250 matching transfer rows in the selected date window.
                  </div>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => void runManualSearch()}
                    disabled={manualLoading}
                  >
                    {manualLoading ? (
                      <Icons.Spinner className="mr-2 h-4 w-4 animate-spin" />
                    ) : (
                      <Icons.Search className="mr-2 h-4 w-4" />
                    )}
                    Search
                  </Button>
                </div>

                {manualError ? (
                  <div className="text-destructive rounded-md border p-3 text-sm">
                    {manualError}
                  </div>
                ) : null}

                {manualSearched ? (
                  <ScrollArea className="max-h-72">
                    <div className="space-y-2 pr-3">
                      {filteredManualResults.length > 0 ? (
                        filteredManualResults.map((candidate) => (
                          <CandidateButton
                            key={candidate.activity.id}
                            candidate={candidate}
                            accountMap={accountMap}
                            selected={selectedCandidate?.activity.id === candidate.activity.id}
                            onSelect={() => setSelectedCandidate(candidate)}
                          />
                        ))
                      ) : (
                        <div className="text-muted-foreground rounded-md border p-3 text-sm">
                          No eligible transfers match the current filters.
                        </div>
                      )}
                    </div>
                  </ScrollArea>
                ) : null}
              </div>
            </>
          )}
        </div>

        <SheetFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={isProcessing}>
            Cancel
          </Button>
          {mode === "link" ? (
            <Button
              onClick={() => void confirmLink()}
              disabled={!selectedCandidate || isProcessing}
            >
              {isProcessing ? (
                <Icons.Spinner className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <Icons.Link className="mr-2 h-4 w-4" />
              )}
              Link transfers
            </Button>
          ) : (
            <Button onClick={() => void confirmUnlink()} disabled={!counterpart || isProcessing}>
              {isProcessing ? (
                <Icons.Spinner className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <Icons.Unlink className="mr-2 h-4 w-4" />
              )}
              Unlink transfers
            </Button>
          )}
        </SheetFooter>
      </SheetContent>
    </Sheet>
  );
}
