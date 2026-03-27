'use client';

import { useState, useEffect } from 'react';
import { CertificateCard } from './certificate-card';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { Loader2, FileX, Plus } from 'lucide-react';
import { CertificateUploadForm } from './certificate-upload-form';
import type { CertificateStatus } from '@/types';

interface Certificate {
  id: string;
  title: string;
  organization: string;
  description: string | null;
  fileName: string | null;
  fileUrl: string | null;
  verifierEmail: string;
  status: CertificateStatus;
  publicLinkId: string | null;
  qrCodeUrl: string | null;
  createdAt: string;
}

interface CertificateListProps {
  studentId: string;
}

export function CertificateList({ studentId }: CertificateListProps) {
  const [certificates, setCertificates] = useState<Certificate[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchCertificates = async () => {
    try {
      setLoading(true);
      const response = await fetch(`/api/certificates?studentId=${studentId}`);

      if (!response.ok) {
        throw new Error('Failed to fetch certificates');
      }

      const data = await response.json();
      setCertificates(data);
    } catch (err) {
      console.error('Error fetching certificates:', err);
      setError('Failed to load certificates');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCertificates();
  }, [studentId]);

  const handleUpload = async (data: {
    title: string;
    organization: string;
    description?: string;
    verifierEmail: string;
    fileUrl?: string;
    fileName?: string;
  }) => {
    const response = await fetch('/api/certificates', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        studentId,
        ...data,
      }),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || 'Failed to create certificate');
    }

    await fetchCertificates();
  };

  const handleDelete = async (id: string) => {
    try {
      const response = await fetch(`/api/certificates/${id}`, {
        method: 'DELETE',
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Failed to delete certificate');
      }

      setCertificates((prev) => prev.filter((cert) => cert.id !== id));
    } catch (err) {
      console.error('Error deleting certificate:', err);
    }
  };

  const pendingCount = certificates.filter((c) => c.status === 'pending').length;
  const verifiedCount = certificates.filter((c) => c.status === 'verified').length;
  const rejectedCount = certificates.filter((c) => c.status === 'rejected').length;

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="text-center py-12">
        <p className="text-destructive">{error}</p>
        <Button variant="outline" onClick={fetchCertificates} className="mt-4">
          Try Again
        </Button>
      </div>
    );
  }

  if (certificates.length === 0) {
    return (
      <div className="text-center py-12">
        <FileX className="h-16 w-16 mx-auto text-muted-foreground mb-4" />
        <h3 className="text-lg font-medium mb-2">No certificates yet</h3>
        <p className="text-muted-foreground mb-4">
          Upload your first certificate to get started with verification.
        </p>
        <CertificateUploadForm onUpload={handleUpload} />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex gap-4">
          <Badge variant="secondary" className="gap-1">
            {pendingCount} Pending
          </Badge>
          <Badge variant="secondary" className="gap-1">
            {verifiedCount} Verified
          </Badge>
          <Badge variant="secondary" className="gap-1">
            {rejectedCount} Rejected
          </Badge>
        </div>
        <CertificateUploadForm onUpload={handleUpload} />
      </div>

      <Tabs defaultValue="all" className="w-full">
        <TabsList>
          <TabsTrigger value="all">All ({certificates.length})</TabsTrigger>
          <TabsTrigger value="pending">Pending ({pendingCount})</TabsTrigger>
          <TabsTrigger value="verified">Verified ({verifiedCount})</TabsTrigger>
          <TabsTrigger value="rejected">Rejected ({rejectedCount})</TabsTrigger>
        </TabsList>

        <TabsContent value="all" className="mt-6">
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            {certificates.map((cert) => (
              <CertificateCard
                key={cert.id}
                {...cert}
                onDelete={handleDelete}
              />
            ))}
          </div>
        </TabsContent>

        <TabsContent value="pending" className="mt-6">
          {pendingCount === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              No pending certificates
            </div>
          ) : (
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
              {certificates
                .filter((c) => c.status === 'pending')
                .map((cert) => (
                  <CertificateCard
                    key={cert.id}
                    {...cert}
                    onDelete={handleDelete}
                  />
                ))}
            </div>
          )}
        </TabsContent>

        <TabsContent value="verified" className="mt-6">
          {verifiedCount === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              No verified certificates yet
            </div>
          ) : (
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
              {certificates
                .filter((c) => c.status === 'verified')
                .map((cert) => (
                  <CertificateCard key={cert.id} {...cert} />
                ))}
            </div>
          )}
        </TabsContent>

        <TabsContent value="rejected" className="mt-6">
          {rejectedCount === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              No rejected certificates
            </div>
          ) : (
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
              {certificates
                .filter((c) => c.status === 'rejected')
                .map((cert) => (
                  <CertificateCard key={cert.id} {...cert} />
                ))}
            </div>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}
