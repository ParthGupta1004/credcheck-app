export type CertificateStatus = 'pending' | 'verified' | 'rejected';

export interface Certificate {
  id: string;
  studentId: string;
  title: string;
  organization: string;
  description: string | null;
  fileUrl: string | null;
  fileName: string | null;
  verifierEmail: string;
  verifierId: string | null;
  status: CertificateStatus;
  comments: string | null;
  publicLinkId: string | null;
  qrCodeUrl: string | null;
  issuedAt: Date | null;
  verifiedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface User {
  id: string;
  email: string;
  name: string | null;
  image: string | null;
  role: 'student' | 'verifier' | 'admin';
  college: string | null;
  degree: string | null;
  batch: string | null;
  verified: boolean;
}

export interface CertificateFormData {
  title: string;
  organization: string;
  description?: string;
  verifierEmail: string;
  file?: File;
}

export interface UserProfileData {
  college?: string;
  degree?: string;
  batch?: string;
  name?: string;
}
