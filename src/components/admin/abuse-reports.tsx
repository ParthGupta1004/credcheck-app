"use client";

import { useState, useEffect } from "react";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { Search, AlertTriangle, Check, Loader2, ExternalLink } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface AbuseReport {
  id: string;
  reason: string;
  status: string;
  createdAt: string;
  reviewedAt: string | null;
  reporter: {
    id: string;
    name: string | null;
    email: string;
    image: string | null;
  };
  certificate: {
    id: string;
    title: string;
    organization: string;
    publicLinkId: string;
    student: {
      name: string | null;
      email: string;
    };
  };
}

interface AbuseReportsProps {
  reports: AbuseReport[];
  onReportResolved?: () => void;
}

export function AbuseReports({
  reports: initialReports,
  onReportResolved,
}: AbuseReportsProps) {
  const [reports, setReports] = useState<AbuseReport[]>(initialReports);
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [selectedReport, setSelectedReport] = useState<AbuseReport | null>(null);
  const [resolutionNote, setResolutionNote] = useState("");
  const [actionLoading, setActionLoading] = useState(false);
  const { toast } = useToast();

  useEffect(() => {
    setReports(initialReports);
  }, [initialReports]);

  const filteredReports = reports.filter((report) => {
    const matchesSearch =
      report.reason.toLowerCase().includes(searchQuery.toLowerCase()) ||
      report.certificate.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      report.certificate.organization.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (report.reporter.name?.toLowerCase().includes(searchQuery.toLowerCase()) ?? false);

    const matchesStatus = statusFilter === "all" || report.status === statusFilter;

    return matchesSearch && matchesStatus;
  });

  const getStatusBadgeVariant = (status: string) => {
    switch (status) {
      case "resolved":
        return "default";
      case "reviewed":
        return "secondary";
      default:
        return "destructive";
    }
  };

  const handleResolve = async () => {
    if (!selectedReport) return;

    setActionLoading(true);
    try {
      const response = await fetch(
        `/api/admin/abuse-reports/${selectedReport.id}/resolve`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ note: resolutionNote }),
        }
      );

      if (!response.ok) {
        throw new Error("Failed to resolve report");
      }

      setReports((prev) =>
        prev.map((report) =>
          report.id === selectedReport.id
            ? {
                ...report,
                status: "resolved",
                reviewedAt: new Date().toISOString(),
              }
            : report
        )
      );

      toast({
        title: "Report resolved",
        description: "The abuse report has been marked as resolved",
      });

      onReportResolved?.();
    } catch (error) {
      toast({
        variant: "destructive",
        title: "Error",
        description: "Failed to resolve abuse report",
      });
    } finally {
      setActionLoading(false);
      setSelectedReport(null);
      setResolutionNote("");
    }
  };

  const getInitials = (name: string | null, email: string) => {
    if (name) {
      return name
        .split(" ")
        .map((n) => n[0])
        .join("")
        .toUpperCase()
        .slice(0, 2);
    }
    return email.slice(0, 2).toUpperCase();
  };

  const pendingCount = reports.filter((r) => r.status === "pending").length;

  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex flex-1 gap-4">
          <div className="relative flex-1">
            <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search reports..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-8"
            />
          </div>
          <Select value={statusFilter} onValueChange={setStatusFilter}>
            <SelectTrigger className="w-[180px]">
              <SelectValue placeholder="Filter by status" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Reports</SelectItem>
              <SelectItem value="pending">Pending ({pendingCount})</SelectItem>
              <SelectItem value="reviewed">Reviewed</SelectItem>
              <SelectItem value="resolved">Resolved</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      <div className="rounded-lg border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Certificate</TableHead>
              <TableHead>Reason</TableHead>
              <TableHead>Reported By</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Reported</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filteredReports.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} className="h-24 text-center">
                  No abuse reports found.
                </TableCell>
              </TableRow>
            ) : (
              filteredReports.map((report) => (
                <TableRow key={report.id}>
                  <TableCell>
                    <div>
                      <div className="font-medium">{report.certificate.title}</div>
                      <div className="text-sm text-muted-foreground">
                        {report.certificate.organization}
                      </div>
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="max-w-[200px] truncate text-sm">
                      {report.reason}
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <Avatar className="h-6 w-6">
                        <AvatarImage src={report.reporter.image ?? undefined} />
                        <AvatarFallback className="text-xs">
                          {getInitials(report.reporter.name, report.reporter.email)}
                        </AvatarFallback>
                      </Avatar>
                      <div className="text-sm">
                        {report.reporter.name ?? report.reporter.email}
                      </div>
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge variant={getStatusBadgeVariant(report.status)}>
                      {report.status}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <div className="text-sm">
                      {new Date(report.createdAt).toLocaleDateString()}
                    </div>
                  </TableCell>
                  <TableCell className="text-right">
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => setSelectedReport(report)}
                    >
                      {report.status === "pending" ? (
                        <>
                          <AlertTriangle className="h-4 w-4 mr-1 text-orange-500" />
                          Review
                        </>
                      ) : (
                        "View"
                      )}
                    </Button>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>

      <Dialog
        open={!!selectedReport}
        onOpenChange={() => {
          setSelectedReport(null);
          setResolutionNote("");
        }}
      >
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-orange-500" />
              Abuse Report Details
            </DialogTitle>
            <DialogDescription>
              Review the report details and take appropriate action.
            </DialogDescription>
          </DialogHeader>
          {selectedReport && (
            <div className="space-y-4">
              <div className="grid gap-4 sm:grid-cols-2">
                <div className="space-y-2">
                  <h4 className="text-sm font-medium">Certificate</h4>
                  <div className="rounded-lg border p-3">
                    <div className="font-medium">
                      {selectedReport.certificate.title}
                    </div>
                    <div className="text-sm text-muted-foreground">
                      {selectedReport.certificate.organization}
                    </div>
                    <div className="mt-2 text-xs text-muted-foreground">
                      Student: {selectedReport.certificate.student.name ?? selectedReport.certificate.student.email}
                    </div>
                    <a
                      href={`/certificate/${selectedReport.certificate.publicLinkId}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="mt-2 inline-flex items-center gap-1 text-sm text-blue-600 hover:underline"
                    >
                      <ExternalLink className="h-3 w-3" />
                      View Certificate
                    </a>
                  </div>
                </div>

                <div className="space-y-2">
                  <h4 className="text-sm font-medium">Reported By</h4>
                  <div className="flex items-center gap-3 rounded-lg border p-3">
                    <Avatar className="h-10 w-10">
                      <AvatarImage src={selectedReport.reporter.image ?? undefined} />
                      <AvatarFallback>
                        {getInitials(
                          selectedReport.reporter.name,
                          selectedReport.reporter.email
                        )}
                      </AvatarFallback>
                    </Avatar>
                    <div>
                      <div className="font-medium">
                        {selectedReport.reporter.name ?? "Unnamed"}
                      </div>
                      <div className="text-sm text-muted-foreground">
                        {selectedReport.reporter.email}
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <div className="space-y-2">
                <h4 className="text-sm font-medium">Reason for Report</h4>
                <div className="rounded-lg border p-3 bg-muted/50">
                  {selectedReport.reason}
                </div>
              </div>

              <div className="grid gap-4 sm:grid-cols-2">
                <div className="space-y-2">
                  <h4 className="text-sm font-medium">Status</h4>
                  <Badge variant={getStatusBadgeVariant(selectedReport.status)}>
                    {selectedReport.status}
                  </Badge>
                </div>
                <div className="space-y-2">
                  <h4 className="text-sm font-medium">Reported On</h4>
                  <div className="text-sm">
                    {new Date(selectedReport.createdAt).toLocaleString()}
                  </div>
                </div>
              </div>

              {selectedReport.status === "pending" && (
                <div className="space-y-2">
                  <h4 className="text-sm font-medium">Resolution Note</h4>
                  <Textarea
                    placeholder="Add a note about how this report was resolved..."
                    value={resolutionNote}
                    onChange={(e) => setResolutionNote(e.target.value)}
                    rows={3}
                  />
                </div>
              )}

              {selectedReport.status === "pending" && (
                <DialogFooter>
                  <Button
                    variant="outline"
                    onClick={() => {
                      setSelectedReport(null);
                      setResolutionNote("");
                    }}
                  >
                    Cancel
                  </Button>
                  <Button onClick={handleResolve} disabled={actionLoading}>
                    {actionLoading ? (
                      <Loader2 className="h-4 w-4 animate-spin" />
                    ) : (
                      <>
                        <Check className="h-4 w-4 mr-2" />
                        Mark as Resolved
                      </>
                    )}
                  </Button>
                </DialogFooter>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>

      <div className="text-sm text-muted-foreground">
        Showing {filteredReports.length} of {reports.length} reports
      </div>
    </div>
  );
}
