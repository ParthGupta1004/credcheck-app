import { Metadata } from 'next'
import { notFound } from 'next/navigation'
import { db } from '@/lib/db'
import { CertificatePageClient } from './client'

interface PageProps {
  params: Promise<{ id: string }>
}

export async function generateMetadata({ params }: PageProps): Promise<Metadata> {
  const { id } = await params

  const certificate = await db.certificate.findUnique({
    where: { publicLinkId: id },
    select: {
      title: true,
      organization: true,
      status: true,
    }
  })

  if (!certificate || certificate.status !== 'verified') {
    return {
      title: 'Certificate Not Found - CredCheck',
    }
  }

  return {
    title: `${certificate.title} - ${certificate.organization} | CredCheck`,
    description: `Verified certificate: ${certificate.title} issued by ${certificate.organization}`,
  }
}

export default async function CertificatePage({ params }: PageProps) {
  const { id } = await params

  const certificate = await db.certificate.findUnique({
    where: { publicLinkId: id },
    include: {
      student: {
        select: {
          id: true,
          name: true,
          email: true,
          college: true,
          degree: true,
          batch: true,
        }
      },
      verifier: {
        select: {
          id: true,
          name: true,
          email: true,
        }
      }
    }
  })

  if (!certificate) {
    notFound()
  }

  // Only show verified certificates
  if (certificate.status !== 'verified') {
    return (
      <div className="min-h-screen bg-slate-50 dark:bg-slate-900 flex items-center justify-center p-4">
        <div className="max-w-md w-full text-center">
          <div className="bg-white dark:bg-slate-800 rounded-2xl shadow-xl p-8">
            <div className="w-16 h-16 bg-amber-100 dark:bg-amber-900/30 rounded-full flex items-center justify-center mx-auto mb-4">
              <svg
                className="w-8 h-8 text-amber-600 dark:text-amber-400"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
                />
              </svg>
            </div>
            <h1 className="text-xl font-bold text-slate-800 dark:text-slate-100 mb-2">
              Certificate Not Verified
            </h1>
            <p className="text-slate-600 dark:text-slate-400">
              This certificate is pending verification or has been rejected.
              Please contact the issuing organization for more information.
            </p>
          </div>
        </div>
      </div>
    )
  }

  // Prepare certificate data for client component
  const certificateData = {
    id: certificate.id,
    title: certificate.title,
    organization: certificate.organization,
    description: certificate.description,
    fileUrl: certificate.fileUrl,
    fileName: certificate.fileName,
    status: certificate.status,
    issuedAt: certificate.issuedAt?.toISOString() ?? null,
    verifiedAt: certificate.verifiedAt?.toISOString() ?? null,
    publicLinkId: certificate.publicLinkId as string,
    student: {
      name: certificate.student.name,
      college: certificate.student.college,
      degree: certificate.student.degree,
    },
    verifier: certificate.verifier ? {
      name: certificate.verifier.name,
      email: certificate.verifier.email,
    } : null,
    verifierEmail: certificate.verifierEmail,
  }

  return <CertificatePageClient certificate={certificateData} />
}
