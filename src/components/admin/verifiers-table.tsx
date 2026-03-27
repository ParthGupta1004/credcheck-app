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
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { Search, Check, X, ExternalLink, Loader2 } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface VerifierRequest {
  id: string;
  organizationName: string;
  organizationEmail: string;
  description: string | null;
  website: string | null;
  logoUrl: string | null;
  status: string;
  requestedAt: string;
  reviewedAt: string | null;
  user: {
    id: string;
    name: string | null;
    email: string;
    image: string | null;
  };
}

interface VerifiersTableProps {
  requests: VerifierRequest[];
  onRequestHandled?: () => void;
}

export function VerifiersTable({
  requests: initialRequests,
  onRequestHandled,
}: VerifiersTableProps) {
  const [requests, setRequests] = useState<VerifierRequest[]>(initialRequests);
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [selectedRequest, setSelectedRequest] = useState<VerifierRequest | null>(
    null
  );
  const [actionLoading, setActionLoading] = useState(false);
  const { toast } = useToast();

  useEffect(() => {
    setRequests(initialRequests);
  }, [initialRequests]);

  const filteredRequests = requests.filter((request) => {
    const matchesSearch =
      request.organizationName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      request.organizationEmail.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (request.user.name?.toLowerCase().includes(searchQuery.toLowerCase()) ?? false);

    const matchesStatus = statusFilter === "all" || request.status === statusFilter;

    return matchesSearch && matchesStatus;
  });

  const getStatusBadgeVariant = (status: string) => {
    switch (status) {
      case "approved":
        return "default";
      case "rejected":
        return "destructive";
      default:
        return "secondary";
    }
  };

  const handleApprove = async () => {
    if (!selectedRequest) return;

    setActionLoading(true);
    try {
      const response = await fetch(
        `/api/admin/verifier-requests/${selectedRequest.id}/approve`,
        {
          method: "POST",
        }
      );

      if (!response.ok) {
        throw new Error("Failed to approve request");
      }

      setRequests((prev) =>
        prev.map((req) =>
          req.id === selectedRequest.id
            ? { ...req, status: "approved", reviewedAt: new Date().toISOString() }
            : req
        )
      );

      toast({
        title: "Request approved",
        description: `${selectedRequest.organizationName} has been approved as a verifier`,
      });

      onRequestHandled?.();
    } catch (error) {
      toast({
        variant: "destructive",
        title: "Error",
        description: "Failed to approve verifier request",
      });
    } finally {
      setActionLoading(false);
      setSelectedRequest(null);
    }
  };

  const handleReject = async () => {
    if (!selectedRequest) return;

    setActionLoading(true);
    try {
      const response = await fetch(
        `/api/admin/verifier-requests/${selectedRequest.id}/reject`,
        {
          method: "POST",
        }
      );

      if (!response.ok) {
        throw new Error("Failed to reject request");
      }

      setRequests((prev) =>
        prev.map((req) =>
          req.id === selectedRequest.id
            ? { ...req, status: "rejected", reviewedAt: new Date().toISOString() }
            : req
        )
      );

      toast({
        title: "Request rejected",
        description: `Verifier request from ${selectedRequest.organizationName} has been rejected`,
      });

      onRequestHandled?.();
    } catch (error) {
      toast({
        variant: "destructive",
        title: "Error",
        description: "Failed to reject verifier request",
      });
    } finally {
      setActionLoading(false);
      setSelectedRequest(null);
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

  const pendingCount = requests.filter((r) => r.status === "pending").length;

  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex flex-1 gap-4">
          <div className="relative flex-1">
            <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search by organization or requester..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-8"
            />
          </div>
          <div className="flex gap-2">
            <Button
              variant={statusFilter === "all" ? "default" : "outline"}
              size="sm"
              onClick={() => setStatusFilter("all")}
            >
              All
            </Button>
            <Button
              variant={statusFilter === "pending" ? "default" : "outline"}
              size="sm"
              onClick={() => setStatusFilter("pending")}
            >
              Pending ({pendingCount})
            </Button>
            <Button
              variant={statusFilter === "approved" ? "default" : "outline"}
              size="sm"
              onClick={() => setStatusFilter("approved")}
            >
              Approved
            </Button>
            <Button
              variant={statusFilter === "rejected" ? "default" : "outline"}
              size="sm"
              onClick={() => setStatusFilter("rejected")}
            >
              Rejected
            </Button>
          </div>
        </div>
      </div>

      <div className="rounded-lg border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Organization</TableHead>
              <TableHead>Requester</TableHead>
              <TableHead>Website</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Requested</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filteredRequests.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} className="h-24 text-center">
                  No verifier requests found.
                </TableCell>
              </TableRow>
            ) : (
              filteredRequests.map((request) => (
                <TableRow key={request.id}>
                  <TableCell>
                    <div className="flex items-center gap-3">
                      <Avatar className="h-10 w-10 rounded-lg">
                        <AvatarImage src={request.logoUrl ?? undefined} />
                        <AvatarFallback className="rounded-lg">
                          {request.organizationName.slice(0, 2).toUpperCase()}
                        </AvatarFallback>
                      </Avatar>
                      <div>
                        <div className="font-medium">
                          {request.organizationName}
                        </div>
                        <div className="text-sm text-muted-foreground">
                          {request.organizationEmail}
                        </div>
                      </div>
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <Avatar className="h-6 w-6">
                        <AvatarImage src={request.user.image ?? undefined} />
                        <AvatarFallback className="text-xs">
                          {getInitials(request.user.name, request.user.email)}
                        </AvatarFallback>
                      </Avatar>
                      <div className="text-sm">
                        {request.user.name ?? request.user.email}
                      </div>
                    </div>
                  </TableCell>
                  <TableCell>
                    {request.website ? (
                      <a
                        href={request.website}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex items-center gap-1 text-sm text-blue-600 hover:underline"
                      >
                        <ExternalLink className="h-3 w-3" />
                        Visit
                      </a>
                    ) : (
                      <span className="text-muted-foreground">-</span>
                    )}
                  </TableCell>
                  <TableCell>
                    <Badge variant={getStatusBadgeVariant(request.status)}>
                      {request.status}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <div className="text-sm">
                      {new Date(request.requestedAt).toLocaleDateString()}
                    </div>
                    {request.reviewedAt && (
                      <div className="text-xs text-muted-foreground">
                        Reviewed: {new Date(request.reviewedAt).toLocaleDateString()}
                      </div>
                    )}
                  </TableCell>
                  <TableCell className="text-right">
                    {request.status === "pending" ? (
                      <div className="flex justify-end gap-2">
                        <Button
                          size="sm"
                          variant="outline"
                          className="text-green-600 hover:text-green-700"
                          onClick={() => setSelectedRequest(request)}
                        >
                          <Check className="h-4 w-4" />
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          className="text-red-600 hover:text-red-700"
                          onClick={() => {
                            setSelectedRequest(request);
                          }}
                        >
                          <X className="h-4 w-4" />
                        </Button>
                      </div>
                    ) : (
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => setSelectedRequest(request)}
                      >
                        View
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>

      <Dialog
        open={!!selectedRequest}
        onOpenChange={() => setSelectedRequest(null)}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Verifier Request Details</DialogTitle>
            <DialogDescription>
              Review the organization details before making a decision.
            </DialogDescription>
          </DialogHeader>
          {selectedRequest && (
            <div className="space-y-4">
              <div className="flex items-center gap-4">
                <Avatar className="h-16 w-16 rounded-lg">
                  <AvatarImage src={selectedRequest.logoUrl ?? undefined} />
                  <AvatarFallback className="rounded-lg text-xl">
                    {selectedRequest.organizationName.slice(0, 2).toUpperCase()}
                  </AvatarFallback>
                </Avatar>
                <div>
                  <h3 className="text-lg font-semibold">
                    {selectedRequest.organizationName}
                  </h3>
                  <p className="text-sm text-muted-foreground">
                    {selectedRequest.organizationEmail}
                  </p>
                </div>
              </div>

              <div className="space-y-2">
                <h4 className="text-sm font-medium">Description</h4>
                <p className="text-sm text-muted-foreground">
                  {selectedRequest.description ?? "No description provided"}
                </p>
              </div>

              {selectedRequest.website && (
                <div className="space-y-2">
                  <h4 className="text-sm font-medium">Website</h4>
                  <a
                    href={selectedRequest.website}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-1 text-sm text-blue-600 hover:underline"
                  >
                    <ExternalLink className="h-3 w-3" />
                    {selectedRequest.website}
                  </a>
                </div>
              )}

              <div className="space-y-2">
                <h4 className="text-sm font-medium">Requester</h4>
                <div className="flex items-center gap-2">
                  <Avatar className="h-8 w-8">
                    <AvatarImage src={selectedRequest.user.image ?? undefined} />
                    <AvatarFallback>
                      {getInitials(
                        selectedRequest.user.name,
                        selectedRequest.user.email
                      )}
                    </AvatarFallback>
                  </Avatar>
                  <div>
                    <div className="text-sm font-medium">
                      {selectedRequest.user.name ?? "Unnamed"}
                    </div>
                    <div className="text-xs text-muted-foreground">
                      {selectedRequest.user.email}
                    </div>
                  </div>
                </div>
              </div>

              {selectedRequest.status === "pending" && (
                <DialogFooter className="gap-2">
                  <Button
                    variant="outline"
                    className="flex-1"
                    onClick={handleReject}
                    disabled={actionLoading}
                  >
                    {actionLoading ? (
                      <Loader2 className="h-4 w-4 animate-spin" />
                    ) : (
                      <>
                        <X className="h-4 w-4 mr-2" />
                        Reject
                      </>
                    )}
                  </Button>
                  <Button
                    className="flex-1"
                    onClick={handleApprove}
                    disabled={actionLoading}
                  >
                    {actionLoading ? (
                      <Loader2 className="h-4 w-4 animate-spin" />
                    ) : (
                      <>
                        <Check className="h-4 w-4 mr-2" />
                        Approve
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
        Showing {filteredRequests.length} of {requests.length} requests
      </div>
    </div>
  );
}
