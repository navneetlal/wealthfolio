import { getAgentAccessStatus, isDesktop, isWeb } from "@/adapters";
import { usePlatform } from "@/hooks/use-platform";
import { QueryKeys } from "@/lib/query-keys";
import { useQuery } from "@tanstack/react-query";
import { Alert, AlertDescription, AlertTitle } from "@wealthfolio/ui/components/ui/alert";
import { Button } from "@wealthfolio/ui/components/ui/button";
import { EmptyPlaceholder } from "@wealthfolio/ui/components/ui/empty-placeholder";
import { Icons } from "@wealthfolio/ui/components/ui/icons";
import { Separator } from "@wealthfolio/ui/components/ui/separator";
import { SettingsHeader } from "../settings-header";
import { AuditLogTable } from "./components/audit-log-table";
import { McpHero } from "./components/mcp-hero";
import { McpModuleCard } from "./components/mcp-module-card";
import { McpServerCard } from "./components/mcp-server-card";
import { PatTable } from "./components/pat-table";
import { useMcpServer } from "./hooks/use-mcp-server";

function DesktopAgentAccess() {
  const { status } = useMcpServer();
  const serverUrl =
    status?.running && status.port ? `http://127.0.0.1:${status.port}/mcp` : undefined;

  return (
    <>
      <McpModuleCard />
      {status?.enabled && (
        <>
          <McpServerCard />
          <PatTable serverUrl={serverUrl} />
          <AuditLogTable
            disabledNotice={
              !status.auditEnabled
                ? "Audit logging is off — new activity will not be recorded."
                : undefined
            }
          />
        </>
      )}
    </>
  );
}

function WebAgentAccess() {
  const {
    data: status,
    isError,
    refetch,
  } = useQuery({
    queryKey: [QueryKeys.AGENT_ACCESS_STATUS],
    queryFn: getAgentAccessStatus,
    enabled: isWeb,
  });

  // Full URL (origin + endpoint) for copy-paste configs; endpoint is relative.
  const serverUrl =
    status?.mcpEnabled && typeof window !== "undefined"
      ? new URL(status.endpoint, window.location.origin).toString()
      : undefined;

  return (
    <>
      {isError && (
        <Alert variant="destructive">
          <Icons.AlertTriangle className="h-4 w-4" />
          <AlertTitle>Failed to load MCP status</AlertTitle>
          <AlertDescription className="flex items-center justify-between gap-4">
            <span>Could not check whether the MCP endpoint is enabled on this server.</span>
            <Button variant="outline" size="sm" onClick={() => void refetch()}>
              Retry
            </Button>
          </AlertDescription>
        </Alert>
      )}
      {status && (
        <McpHero
          active={status.mcpEnabled}
          title={status.mcpEnabled ? "AI Agent Access · enabled" : "AI Agent Access · off"}
          description={
            status.mcpEnabled
              ? `AI agents can connect to ${status.endpoint} on this server using a scoped access token.`
              : "AI Agent Access is off on this server. Enable it to let AI agents read and act on your portfolio over MCP."
          }
          hint={
            status.mcpEnabled ? undefined : (
              <>
                Set <code className="font-mono">WF_MCP_ENABLED=true</code> and restart the server to
                enable the endpoint, then create a token here.
              </>
            )
          }
        />
      )}
      {status?.mcpEnabled && (
        <>
          <PatTable serverUrl={serverUrl} />
          <AuditLogTable
            disabledNotice={
              !status.auditEnabled
                ? "Audit logging is off (WF_MCP_AUDIT_ENABLED=false) — new activity will not be recorded."
                : undefined
            }
          />
        </>
      )}
    </>
  );
}

export default function AgentAccessPage() {
  const { isMobile, loading } = usePlatform();

  return (
    <div className="space-y-6">
      <SettingsHeader
        heading="AI Agent Access"
        text="Let AI agents access your portfolio over MCP. Each token's scopes control what it can do."
      />
      <Separator />

      {loading ? null : isDesktop && isMobile ? (
        <EmptyPlaceholder>
          <EmptyPlaceholder.Icon name="Brain" />
          <EmptyPlaceholder.Title>Not available on mobile</EmptyPlaceholder.Title>
          <EmptyPlaceholder.Description>
            AI Agent Access is managed on desktop or web.
          </EmptyPlaceholder.Description>
        </EmptyPlaceholder>
      ) : isDesktop ? (
        <DesktopAgentAccess />
      ) : (
        <WebAgentAccess />
      )}
    </div>
  );
}
