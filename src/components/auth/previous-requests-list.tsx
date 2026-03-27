"use client";

import { useEffect, useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { formatDistanceToNow } from "date-fns";
import { History, Clock, CheckCircle2, XCircle, AlertCircle, RefreshCw } from "lucide-react";

interface VerifierRequest {
  id: string;
  organizationName: string;
  organizationEmail: string;
  status: "pending" | "approved" | "rejected";
  website?: string | null;
  description?: string | null;
  requestedAt: string;
  reviewedAt?: string | null;
}

const statusConfig = {
  pending: {
    icon: Clock,
    label: "Pending Review",
    color: "bg-yellow-100 text-yellow-800 border-yellow-200",
    badgeVariant: "secondary" as const,
  },
  approved: {
    icon: CheckCircle2,
    label: "Approved",
    color: "bg-green-100 text-green-800 border-green-200",
    badgeVariant: "default" as const,
  },
  rejected: {
    icon: XCircle,
    label: "Rejected",
    color: "bg-red-100 text-red-800 border-red-200",
    badgeVariant: "destructive" as const,
  },
};

export function PreviousRequestsList() {
  const [requests, setRequests] = useState<VerifierRequest[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchRequests = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const response = await fetch("/api/verifier-requests/my-requests");
      if (!response.ok) {
        throw new Error("Failed to fetch requests");
      }
      const data = await response.json();
      setRequests(data.requests || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load requests");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchRequests();
  }, []);

  if (isLoading) {
    return (
      <Card className="w-full">
        <CardHeader>
          <CardTitle className="text-lg flex items-center gap-2">
            <History className="h-5 w-5" />
            Your Previous Requests
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {[1, 2].map((i) => (
            <div key={i} className="space-y-2">
              <Skeleton className="h-5 w-1/2" />
              <Skeleton className="h-4 w-1/4" />
            </div>
          ))}
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Card className="w-full">
        <CardHeader>
          <CardTitle className="text-lg flex items-center gap-2">
            <History className="h-5 w-5" />
            Your Previous Requests
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertDescription className="flex items-center justify-between w-full">
              <span>{error}</span>
              <Button variant="ghost" size="sm" onClick={fetchRequests}>
                <RefreshCw className="h-4 w-4" />
              </Button>
            </AlertDescription>
          </Alert>
        </CardContent>
      </Card>
    );
  }

  if (requests.length === 0) {
    return (
      <Card className="w-full">
        <CardHeader>
          <CardTitle className="text-lg flex items-center gap-2">
            <History className="h-5 w-5" />
            Your Previous Requests
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-muted-foreground text-center py-4">
            You haven&apos;t submitted any verifier requests yet.
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="w-full">
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="text-lg flex items-center gap-2">
            <History className="h-5 w-5" />
            Your Previous Requests
          </CardTitle>
          <Button variant="ghost" size="sm" onClick={fetchRequests}>
            <RefreshCw className="h-4 w-4" />
          </Button>
        </div>
        <CardDescription>
          Track the status of your verifier applications
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-4 max-h-96 overflow-y-auto pr-2">
          {requests.map((request) => {
            const config = statusConfig[request.status];
            const StatusIcon = config.icon;
            
            return (
              <div
                key={request.id}
                className="border rounded-lg p-4 space-y-2"
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="space-y-1">
                    <h4 className="font-medium">{request.organizationName}</h4>
                    <p className="text-sm text-muted-foreground">{request.organizationEmail}</p>
                  </div>
                  <Badge variant={config.badgeVariant} className={config.color}>
                    <StatusIcon className="h-3 w-3 mr-1" />
                    {config.label}
                  </Badge>
                </div>
                <div className="flex items-center gap-4 text-xs text-muted-foreground">
                  <span>
                    Submitted {formatDistanceToNow(new Date(request.requestedAt), { addSuffix: true })}
                  </span>
                  {request.reviewedAt && (
                    <span>
                      Reviewed {formatDistanceToNow(new Date(request.reviewedAt), { addSuffix: true })}
                    </span>
                  )}
                </div>
                {request.website && (
                  <a
                    href={request.website}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-sm text-primary hover:underline"
                  >
                    {request.website}
                  </a>
                )}
              </div>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}
