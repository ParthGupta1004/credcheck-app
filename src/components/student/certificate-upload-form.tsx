'use client';

import { useState, useRef } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import * as z from 'zod';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Upload, Loader2, X, FileText, ImageIcon } from 'lucide-react';

const certificateSchema = z.object({
  title: z.string().min(3, 'Title must be at least 3 characters').max(100, 'Title must be less than 100 characters'),
  organization: z.string().min(2, 'Organization name is required').max(100, 'Organization name is too long'),
  description: z.string().max(500, 'Description must be less than 500 characters').optional(),
  verifierEmail: z.string().email('Please enter a valid email address'),
});

type CertificateFormValues = z.infer<typeof certificateSchema>;

interface CertificateUploadFormProps {
  onUpload: (data: CertificateFormValues & { fileUrl?: string; fileName?: string }) => Promise<void>;
}

export function CertificateUploadForm({ onUpload }: CertificateUploadFormProps) {
  const [open, setOpen] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const form = useForm<CertificateFormValues>({
    resolver: zodResolver(certificateSchema),
    defaultValues: {
      title: '',
      organization: '',
      description: '',
      verifierEmail: '',
    },
  });

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = e.target.files?.[0];
    if (selectedFile) {
      // Validate file type
      const allowedTypes = [
        'application/pdf',
        'image/jpeg',
        'image/jpg',
        'image/png',
        'image/gif',
        'image/webp',
      ];

      if (!allowedTypes.includes(selectedFile.type)) {
        form.setError('root', { message: 'Only PDF and image files are allowed' });
        return;
      }

      // Validate file size (max 10MB)
      if (selectedFile.size > 10 * 1024 * 1024) {
        form.setError('root', { message: 'File size must be less than 10MB' });
        return;
      }

      setFile(selectedFile);
      form.clearErrors('root');
    }
  };

  const removeFile = () => {
    setFile(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const uploadFile = async (): Promise<{ fileUrl: string; fileName: string } | null> => {
    if (!file) return null;

    setUploading(true);
    try {
      const formData = new FormData();
      formData.append('file', file);

      const response = await fetch('/api/upload', {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Failed to upload file');
      }

      const data = await response.json();
      return { fileUrl: data.fileUrl, fileName: data.fileName };
    } catch (error) {
      console.error('Upload error:', error);
      form.setError('root', { message: 'Failed to upload file. Please try again.' });
      return null;
    } finally {
      setUploading(false);
    }
  };

  const onSubmit = async (values: CertificateFormValues) => {
    setIsSubmitting(true);

    try {
      let fileData: { fileUrl?: string; fileName?: string } = {};

      if (file) {
        const uploadedFile = await uploadFile();
        if (uploadedFile) {
          fileData = uploadedFile;
        } else {
          setIsSubmitting(false);
          return;
        }
      }

      await onUpload({ ...values, ...fileData });

      // Reset form
      form.reset();
      setFile(null);
      setOpen(false);
    } catch (error) {
      console.error('Submit error:', error);
      form.setError('root', { message: 'Failed to upload certificate. Please try again.' });
    } finally {
      setIsSubmitting(false);
    }
  };

  const getFileIcon = () => {
    if (!file) return null;
    if (file.type === 'application/pdf') {
      return <FileText className="h-5 w-5 text-red-500" />;
    }
    return <ImageIcon className="h-5 w-5 text-blue-500" />;
  };

  const formatFileSize = (bytes: number) => {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button className="gap-2">
          <Upload className="h-4 w-4" />
          Upload Certificate
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Upload Certificate</DialogTitle>
          <DialogDescription>
            Fill in the details and upload your certificate file for verification.
          </DialogDescription>
        </DialogHeader>

        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
            <FormField
              control={form.control}
              name="title"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Certificate Title *</FormLabel>
                  <FormControl>
                    <Input placeholder="e.g., AWS Solutions Architect Certification" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="organization"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Issuing Organization *</FormLabel>
                  <FormControl>
                    <Input placeholder="e.g., Amazon Web Services" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="description"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Description</FormLabel>
                  <FormControl>
                    <Textarea
                      placeholder="Brief description of the certificate..."
                      className="resize-none"
                      rows={3}
                      {...field}
                    />
                  </FormControl>
                  <FormDescription>
                    Optional description for additional context
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="verifierEmail"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Verifier Email *</FormLabel>
                  <FormControl>
                    <Input
                      type="email"
                      placeholder="verifier@example.com"
                      {...field}
                    />
                  </FormControl>
                  <FormDescription>
                    The email of the person who will verify this certificate
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />

            {/* File Upload */}
            <div className="space-y-2">
              <FormLabel>Certificate File</FormLabel>
              <div className="border-2 border-dashed rounded-lg p-4">
                {file ? (
                  <div className="flex items-center gap-3">
                    {getFileIcon()}
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium truncate">{file.name}</p>
                      <p className="text-xs text-muted-foreground">
                        {formatFileSize(file.size)}
                      </p>
                    </div>
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon"
                      onClick={removeFile}
                      disabled={uploading || isSubmitting}
                    >
                      <X className="h-4 w-4" />
                    </Button>
                  </div>
                ) : (
                  <label className="flex flex-col items-center gap-2 cursor-pointer">
                    <Upload className="h-8 w-8 text-muted-foreground" />
                    <div className="text-center">
                      <p className="text-sm font-medium">Click to upload</p>
                      <p className="text-xs text-muted-foreground">
                        PDF or Image (max 10MB)
                      </p>
                    </div>
                    <input
                      ref={fileInputRef}
                      type="file"
                      className="hidden"
                      accept=".pdf,image/*"
                      onChange={handleFileChange}
                      disabled={uploading || isSubmitting}
                    />
                  </label>
                )}
              </div>
            </div>

            {form.formState.errors.root && (
              <p className="text-sm text-destructive">
                {form.formState.errors.root.message}
              </p>
            )}

            <DialogFooter className="gap-2 sm:gap-0">
              <Button
                type="button"
                variant="outline"
                onClick={() => setOpen(false)}
                disabled={uploading || isSubmitting}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={uploading || isSubmitting}>
                {(uploading || isSubmitting) && (
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                )}
                Submit
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}
