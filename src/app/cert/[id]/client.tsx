'use client'

import { useSyncExternalStore, useCallback } from 'react'
import { motion } from 'framer-motion'
import { CertificateDisplay } from '@/components/certificate/certificate-display'
import { Skeleton } from '@/components/ui/skeleton'

interface CertificateData {
  id: string
  title: string
  organization: string
  description: string | null
  fileUrl: string | null
  fileName: string | null
  status: string
  issuedAt: string | null
  verifiedAt: string | null
  publicLinkId: string
  student: {
    name: string | null
    college: string | null
    degree: string | null
  }
  verifier: {
    name: string | null
    email: string | null
  } | null
  verifierEmail: string
}

interface CertificatePageClientProps {
  certificate: CertificateData
}

// Custom hook for client-side only values using useSyncExternalStore
function useClientValue<T>(clientValue: T, serverValue: T): T {
  const subscribe = useCallback(() => () => {}, [])
  const getSnapshot = useCallback(() => clientValue, [clientValue])
  const getServerSnapshot = useCallback(() => serverValue, [serverValue])
  
  return useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot)
}

export function CertificatePageClient({ certificate }: CertificatePageClientProps) {
  const mounted = useClientValue(true, false)
  const publicUrl = useClientValue(
    typeof window !== 'undefined' ? window.location.href : '',
    ''
  )

  // Convert string dates back to Date objects
  const certificateWithDates = {
    ...certificate,
    issuedAt: certificate.issuedAt ? new Date(certificate.issuedAt) : null,
    verifiedAt: certificate.verifiedAt ? new Date(certificate.verifiedAt) : null,
  }

  if (!mounted) {
    return (
      <div className="min-h-screen bg-slate-50 dark:bg-slate-900 p-4 md:p-8">
        <div className="max-w-5xl mx-auto">
          {/* Loading skeleton */}
          <div className="space-y-6">
            <Skeleton className="h-16 w-full rounded-lg" />
            <Skeleton className="h-96 w-full rounded-2xl" />
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-900 p-4 md:p-8 print:p-0 print:bg-white">
      <div className="max-w-5xl mx-auto">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="text-center mb-8 print:mb-4"
        >
          <div className="flex items-center justify-center gap-3 mb-2">
            <div className="bg-gradient-to-br from-emerald-500 to-teal-600 p-2 rounded-lg shadow-lg">
              <svg
                className="h-6 w-6 text-white"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
                />
              </svg>
            </div>
            <h1 className="text-2xl md:text-3xl font-bold text-slate-800 dark:text-slate-100">
              CredCheck
            </h1>
          </div>
          <p className="text-slate-500 dark:text-slate-400 text-sm">
            Secure Certificate Verification Platform
          </p>
        </motion.div>

        {/* Certificate Display */}
        <CertificateDisplay
          certificate={certificateWithDates}
          publicUrl={publicUrl}
        />

        {/* Footer */}
        <motion.footer
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.5, delay: 0.7 }}
          className="mt-8 text-center text-sm text-slate-500 dark:text-slate-400 print:hidden"
        >
          <p>
            This certificate verification is provided by CredCheck.
            <br />
            For questions or concerns, please contact the issuing organization.
          </p>
        </motion.footer>
      </div>
    </div>
  )
}
