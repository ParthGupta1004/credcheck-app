'use client';

import { useState } from 'react';
import { useSession } from 'next-auth/react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { Label } from '@/components/ui/label';

interface Certificate {
  id: string;
  title: string;
  organization: string;
  description: string | null;
  fileUrl: string | null;
  fileName: string | null;
  status: string;
  comments: string | null;
  createdAt: string;
  student: {
    id: string;
    name: string | null;
    email: string;
    college: string | null;
    degree: string | null;
    batch: string | null;
  };
}

interface VerificationActionProps {
  certificate: Certificate | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  action: 'approve' | 'reject' | null;
  onSuccess: () => void;
}

export function VerificationAction({
  certificate,
  open,
  onOpenChange,
  action,
  onSuccess,
}: VerificationActionProps) {
  const { data: session } = useSession();
  const [comment, setComment] = useState('');
  const [reason, setReason] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async () => {
    if (!certificate || !action) return;

    if (action === 'reject' && !reason.trim()) {
      setError('Rejection reason is required');
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      const endpoint =
        action === 'approve'
          ? `/api/verifications/${certificate.id}/approve`
          : `/api/verifications/${certificate.id}/reject`;

      const body =
        action === 'approve'
          ? { verifierId: session?.user?.id, comments: comment }
          : { verifierId: session?.user?.id, reason };

      const response = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Failed to process request');
      }

      setComment('');
      setReason('');
      onOpenChange(false);
      onSuccess();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setIsLoading(false);
    }
  };

  const handleClose = () => {
    setComment('');
    setReason('');
    setError(null);
    onOpenChange(false);
  };

  if (!certificate || !action) return null;

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent className="sm:max-w-[500px]">
        <DialogHeader>
          <DialogTitle>
            {action === 'approve' ? 'Approve Certificate' : 'Reject Certificate'}
          </DialogTitle>
          <DialogDescription>
            {action === 'approve'
              ? 'Approve this certificate verification request.'
              : 'Reject this certificate verification request. A reason is required.'}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-4">
          {/* Certificate Info */}
          <div className="rounded-lg bg-muted/50 p-4 space-y-2">
            <div className="flex justify-between items-start">
              <div>
                <h4 className="font-medium">{certificate.title}</h4>
                <p className="text-sm text-muted-foreground">
                  {certificate.organization}
                </p>
              </div>
            </div>
            <div className="text-sm text-muted-foreground">
              <span className="font-medium">Student:</span>{' '}
              {certificate.student.name || certificate.student.email}
            </div>
          </div>

          {/* Comment/Reason Input */}
          <div className="space-y-2">
            <Label htmlFor="comment">
              {action === 'approve' ? 'Comment (Optional)' : 'Rejection Reason *'}
            </Label>
            <Textarea
              id="comment"
              placeholder={
                action === 'approve'
                  ? 'Add an optional comment for the approval...'
                  : 'Please provide a reason for rejection...'
              }
              value={action === 'approve' ? comment : reason}
              onChange={(e) =>
                action === 'approve'
                  ? setComment(e.target.value)
                  : setReason(e.target.value)
              }
              rows={3}
              className={action === 'reject' && !reason.trim() && error ? 'border-destructive' : ''}
            />
            {error && (
              <p className="text-sm text-destructive">{error}</p>
            )}
          </div>
        </div>

        <DialogFooter>
          <Button
            type="button"
            variant="outline"
            onClick={handleClose}
            disabled={isLoading}
          >
            Cancel
          </Button>
          <Button
            type="button"
            variant={action === 'approve' ? 'default' : 'destructive'}
            onClick={handleSubmit}
            disabled={isLoading}
          >
            {isLoading
              ? 'Processing...'
              : action === 'approve'
              ? 'Approve'
              : 'Reject'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
