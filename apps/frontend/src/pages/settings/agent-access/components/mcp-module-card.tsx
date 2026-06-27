import { cn } from "@/lib/utils";
import { Switch } from "@wealthfolio/ui/components/ui/switch";
import { useMcpServer } from "../hooks/use-mcp-server";
import { McpHero } from "./mcp-hero";

/** Master feature toggle for AI Agent Access — gates the rest of the page. */
export function McpModuleCard() {
  const { status, isLoading, setEnabledMutation } = useMcpServer();
  const enabled = status?.enabled ?? false;
  const running = status?.running ?? false;

  return (
    <McpHero
      active={enabled}
      title={
        enabled
          ? running
            ? "AI Agent Access · running"
            : "AI Agent Access · enabled"
          : "AI Agent Access · off"
      }
      description={
        enabled
          ? "AI agents can connect over MCP using scoped access tokens. Start the server and create a token below."
          : "AI Agent Access is off. Enable it to let AI agents read and act on your portfolio over MCP."
      }
      hint="Disabling stops the server and hides AI Agent Access. Your tokens are kept but won't work until you re-enable."
      action={
        <label className="flex shrink-0 cursor-pointer select-none items-center gap-2">
          <span className="text-background/55 hidden text-xs font-medium uppercase tracking-widest sm:inline">
            {enabled ? "Enabled" : "Disabled"}
          </span>
          <Switch
            checked={enabled}
            onCheckedChange={(next) => setEnabledMutation.mutate(next)}
            disabled={isLoading || setEnabledMutation.isPending}
            className={cn(
              "data-[state=checked]:bg-warning data-[state=unchecked]:bg-background/15",
              "[&_[data-slot=switch-thumb]]:data-[state=checked]:bg-foreground",
              "[&_[data-slot=switch-thumb]]:data-[state=unchecked]:bg-background/40",
            )}
          />
        </label>
      }
    />
  );
}
