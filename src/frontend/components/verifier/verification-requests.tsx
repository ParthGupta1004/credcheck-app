'use client';

import { useState, useEffect } from 'react';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Search,
  Eye,
  CheckCircle,
  XCircle,
  Clock,
  FileText,
  User,
  Building2,
  Calendar,
  ExternalLink,
} from 'lucide-react';
import { VerificationAction } from './verification-action';

interface Student {
  id: string;
  name: string | null;
  email: string;
  college: string | null;
  degree: string | null;
  batch: string | null;
}

interface Certificate {
  id: string;
  title: string;
  organization: string;
  description: string | null;
  fileUrl: string | null;
  fileName: string | null;
  verifierEmail: string;
  status: string;
  comments: string | null;
  createdAt: string;
  verifiedAt: string | null;
  student: Student;
  verifier: {
    id: string;
    name: string | null;
    email: string;
  } | null;
}

interface Statistics {
  total: number;
  pending: number;
  verified: number;
  rejected: number;
}

interface VerificationRequestsProps {
  verifierEmail?: string;
}

export function VerificationRequests({
  verifierEmail,
}: VerificationRequestsProps) {
  const [certificates, setCertificates] = useState<Certificate[]>([]);
  const [statistics, setStatistics] = useState<Statistics>({
    total: 0,
    pending: 0,
    verified: 0,
    rejected: 0,
  });
  const [isLoading, setIsLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [selectedCertificate, setSelectedCertificate] = useState<Certificate | null>(null);
  const [isDetailOpen, setIsDetailOpen] = useState(false);
  const [actionType, setActionType] = useState<'approve' | 'reject' | null>(null);
  const [isActionOpen, setIsActionOpen] = useState(false);

  const fetchData = async () => {
    if (!verifierEmail) {
      setIsLoading(false);
      return;
    }
    setIsLoading(true);
    try {
      const params = new URLSearchParams({
        verifierEmail,
        status: statusFilter,
        search: searchQuery,
      });
      const response = await fetch(`/api/verifications?${params}`);
      const data = await response.json();
      setCertificates(data.certificates || []);
      setStatistics(data.statistics || { total: 0, pending: 0, verified: 0, rejected: 0 });
    } catch (error) {
      console.error('Failed to fetch certificates:', error);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [statusFilter, verifierEmail]);

  useEffect(() => {
    const debounceTimer = setTimeout(() => {
      fetchData();
    }, 300);
    return () => clearTimeout(debounceTimer);
  }, [searchQuery, verifierEmail]);

  const handleViewDetails = (certificate: Certificate) => {
    setSelectedCertificate(certificate);
    setIsDetailOpen(true);
  };

  const handleAction = (certificate: Certificate, action: 'approve' | 'reject') => {
    setSelectedCertificate(certificate);
    setActionType(action);
    setIsActionOpen(true);
    setIsDetailOpen(false);
  };

  const handleActionSuccess = () => {
    fetchData();
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'verified':
        return (
          <Badge variant="default" className="bg-green-500 hover:bg-green-600">
            <CheckCircle className="w-3 h-3 mr-1" />
            Verified
          </Badge>
        );
      case 'rejected':
        return (
          <Badge variant="destructive">
            <XCircle className="w-3 h-3 mr-1" />
            Rejected
          </Badge>
        );
      default:
        return (
          <Badge variant="secondary">
            <Clock className="w-3 h-3 mr-1" />
            Pending
          </Badge>
        );
    }
  };

  const formatDate = (dateString: string | null) => {
    if (!dateString) return '-';
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    });
  };

  return (
    <div className="space-y-6">
      {/* Statistics Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Total Requests
            </CardTitle>
            <FileText className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{statistics.total}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Pending
            </CardTitle>
            <Clock className="h-4 w-4 text-yellow-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{statistics.pending}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Verified
            </CardTitle>
            <CheckCircle className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{statistics.verified}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Rejected
            </CardTitle>
            <XCircle className="h-4 w-4 text-red-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{statistics.rejected}</div>
          </CardContent>
        </Card>
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search by title, organization, or student..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-10"
          />
        </div>
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-full sm:w-[180px]">
            <SelectValue placeholder="Filter by status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Status</SelectItem>
            <SelectItem value="pending">Pending</SelectItem>
            <SelectItem value="verified">Verified</SelectItem>
            <SelectItem value="rejected">Rejected</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Table */}
      <div className="rounded-lg border bg-card">
        <ScrollArea className="h-[500px]">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Certificate</TableHead>
                <TableHead>Student</TableHead>
                <TableHead>Organization</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Submitted</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center py-8">
                    <div className="flex items-center justify-center gap-2">
                      <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-primary"></div>
                      Loading...
                    </div>
                  </TableCell>
                </TableRow>
              ) : certificates.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center py-8 text-muted-foreground">
                    No verification requests found
                  </TableCell>
                </TableRow>
              ) : (
                certificates.map((cert) => (
                  <TableRow key={cert.id}>
                    <TableCell>
                      <div>
                        <div className="font-medium">{cert.title}</div>
                        {cert.description && (
                          <div className="text-sm text-muted-foreground truncate max-w-[200px]">
                            {cert.description}
                          </div>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <div>
                        <div className="font-medium">
                          {cert.student.name || 'Unknown'}
                        </div>
                        <div className="text-sm text-muted-foreground">
                          {cert.student.email}
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>{cert.organization}</TableCell>
                    <TableCell>{getStatusBadge(cert.status)}</TableCell>
                    <TableCell>{formatDate(cert.createdAt)}</TableCell>
                    <TableCell className="text-right">
                      <div className="flex items-center justify-end gap-2">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => handleViewDetails(cert)}
                        >
                          <Eye className="h-4 w-4" />
                        </Button>
                        {cert.status === 'pending' && (
                          <>
                            <Button
                              variant="ghost"
                              size="sm"
                              className="text-green-600 hover:text-green-700 hover:bg-green-50"
                              onClick={() => handleAction(cert, 'approve')}
                            >
                              <CheckCircle className="h-4 w-4" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              className="text-red-600 hover:text-red-700 hover:bg-red-50"
                              onClick={() => handleAction(cert, 'reject')}
                            >
                              <XCircle className="h-4 w-4" />
                            </Button>
                          </>
                        )}
                      </div>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </ScrollArea>
      </div>

      {/* Detail Sheet */}
      <Sheet open={isDetailOpen} onOpenChange={setIsDetailOpen}>
        <SheetContent className="sm:max-w-lg overflow-y-auto">
          <SheetHeader>
            <SheetTitle>Certificate Details</SheetTitle>
            <SheetDescription>
              View complete information about this certificate request
            </SheetDescription>
          </SheetHeader>
          {selectedCertificate && (
            <div className="mt-6 space-y-6">
              {/* Status Badge */}
              <div>{getStatusBadge(selectedCertificate.status)}</div>

              {/* Certificate Info */}
              <div className="space-y-4">
                <div className="space-y-1">
                  <h4 className="text-sm font-medium text-muted-foreground flex items-center gap-2">
                    <FileText className="h-4 w-4" />
                    Certificate Title
                  </h4>
                  <p className="font-medium">{selectedCertificate.title}</p>
                </div>

                <div className="space-y-1">
                  <h4 className="text-sm font-medium text-muted-foreground flex items-center gap-2">
                    <Building2 className="h-4 w-4" />
                    Organization
                  </h4>
                  <p>{selectedCertificate.organization}</p>
                </div>

                {selectedCertificate.description && (
                  <div className="space-y-1">
                    <h4 className="text-sm font-medium text-muted-foreground">
                      Description
                    </h4>
                    <p className="text-sm">{selectedCertificate.description}</p>
                  </div>
                )}
              </div>

              {/* Student Info */}
              <div className="border-t pt-4">
                <h4 className="font-medium mb-3 flex items-center gap-2">
                  <User className="h-4 w-4" />
                  Student Information
                </h4>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Name:</span>
                    <span>{selectedCertificate.student.name || '-'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Email:</span>
                    <span>{selectedCertificate.student.email}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">College:</span>
                    <span>{selectedCertificate.student.college || '-'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Degree:</span>
                    <span>{selectedCertificate.student.degree || '-'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Batch:</span>
                    <span>{selectedCertificate.student.batch || '-'}</span>
                  </div>
                </div>
              </div>

              {/* Dates */}
              <div className="border-t pt-4">
                <h4 className="font-medium mb-3 flex items-center gap-2">
                  <Calendar className="h-4 w-4" />
                  Timeline
                </h4>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Submitted:</span>
                    <span>{formatDate(selectedCertificate.createdAt)}</span>
                  </div>
                  {selectedCertificate.verifiedAt && (
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">
                        {selectedCertificate.status === 'verified'
                          ? 'Verified:'
                          : 'Processed:'}
                      </span>
                      <span>{formatDate(selectedCertificate.verifiedAt)}</span>
                    </div>
                  )}
                </div>
              </div>

              {/* File */}
              {selectedCertificate.fileUrl && (
                <div className="border-t pt-4">
                  <h4 className="font-medium mb-3">Attached File</h4>
                  <a
                    href={selectedCertificate.fileUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-2 text-sm text-primary hover:underline"
                  >
                    <ExternalLink className="h-4 w-4" />
                    {selectedCertificate.fileName || 'View File'}
                  </a>
                </div>
              )}

              {/* Comments */}
              {selectedCertificate.comments && (
                <div className="border-t pt-4">
                  <h4 className="font-medium mb-2">Comments</h4>
                  <p className="text-sm text-muted-foreground bg-muted/50 rounded-lg p-3">
                    {selectedCertificate.comments}
                  </p>
                </div>
              )}

              {/* Action Buttons for Pending */}
              {selectedCertificate.status === 'pending' && (
                <div className="border-t pt-4 flex gap-3">
                  <Button
                    className="flex-1"
                    onClick={() => handleAction(selectedCertificate, 'approve')}
                  >
                    <CheckCircle className="h-4 w-4 mr-2" />
                    Approve
                  </Button>
                  <Button
                    variant="destructive"
                    className="flex-1"
                    onClick={() => handleAction(selectedCertificate, 'reject')}
                  >
                    <XCircle className="h-4 w-4 mr-2" />
                    Reject
                  </Button>
                </div>
              )}
            </div>
          )}
        </SheetContent>
      </Sheet>

      {/* Action Dialog */}
      <VerificationAction
        certificate={selectedCertificate}
        open={isActionOpen}
        onOpenChange={setIsActionOpen}
        action={actionType}
        onSuccess={handleActionSuccess}
      />
    </div>
  );
}
