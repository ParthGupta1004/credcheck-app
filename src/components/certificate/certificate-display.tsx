'use client'

import { useState } from 'react'
import { motion } from 'framer-motion'
import { Card, CardContent, CardHeader } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog'
import { Label } from '@/components/ui/label'
import { useSession } from 'next-auth/react'
import { useToast } from '@/hooks/use-toast'
import {
  ShieldCheck,
  Calendar,
  Building2,
  User,
  FileText,
  Download,
  Printer,
  ExternalLink,
  CheckCircle2,
  Award,
  AlertTriangle,
  Loader2,
} from 'lucide-react'
import { QRDisplay } from './qr-display'

interface CertificateData {
  id: string
  title: string
  organization: string
  description: string | null
  fileUrl: string | null
  fileName: string | null
  status: string
  issuedAt: Date | null
  verifiedAt: Date | null
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

interface CertificateDisplayProps {
  certificate: CertificateData
  publicUrl: string
}

export function CertificateDisplay({ certificate, publicUrl }: CertificateDisplayProps) {
  const { data: session } = useSession()
  const { toast } = useToast()
  
  const [reportOpen, setReportOpen] = useState(false)
  const [reportReason, setReportReason] = useState('')
  const [reporting, setReporting] = useState(false)

  const handleReportAbuse = async () => {
    if (!reportReason.trim()) {
      toast({
        title: "Error",
        description: "Please provide a reason for reporting",
        variant: "destructive",
      })
      return
    }

    setReporting(true)
    try {
      const res = await fetch('/api/abuse-reports', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          certificateId: certificate.id,
          reason: reportReason,
        })
      })

      if (!res.ok) throw new Error('Failed to report')

      toast({
        title: "Report Submitted",
        description: "Thank you for reporting. Our admin team will review it.",
      })
      setReportOpen(false)
      setReportReason('')
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to submit report. Please try again later.",
        variant: "destructive",
      })
    } finally {
      setReporting(false)
    }
  }
  const formatDate = (date: Date | null) => {
    if (!date) return 'N/A'
    return new Intl.DateTimeFormat('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
    }).format(new Date(date))
  }

  const handlePrint = () => {
    window.print()
  }

  const handleDownloadFile = () => {
    if (certificate.fileUrl) {
      window.open(certificate.fileUrl, '_blank')
    }
  }

  const isImageFile = certificate.fileUrl && /\.(jpg|jpeg|png|gif|webp)$/i.test(certificate.fileUrl)
  const isPdfFile = certificate.fileUrl && /\.pdf$/i.test(certificate.fileUrl)

  return (
    <div className="print:p-0">
      {/* Verification Banner */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="mb-6 print:mb-4"
      >
        <div className="bg-gradient-to-r from-emerald-500 to-teal-500 text-white rounded-lg p-4 shadow-lg">
          <div className="flex items-center justify-center gap-3">
            <ShieldCheck className="h-6 w-6" />
            <span className="font-semibold text-lg">Verified Certificate</span>
            <CheckCircle2 className="h-5 w-5" />
          </div>
        </div>
      </motion.div>

      {/* Main Certificate Card */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, delay: 0.1 }}
      >
        <Card className="border-2 border-slate-200 dark:border-slate-700 shadow-xl overflow-hidden print:shadow-none print:border-slate-300">
          {/* Certificate Header */}
          <CardHeader className="bg-gradient-to-r from-slate-50 to-slate-100 dark:from-slate-800 dark:to-slate-900 border-b border-slate-200 dark:border-slate-700 print:bg-white">
            <div className="flex flex-col md:flex-row items-center justify-between gap-4">
              <div className="flex items-center gap-4">
                <div className="bg-gradient-to-br from-emerald-500 to-teal-600 p-3 rounded-full shadow-lg">
                  <Award className="h-8 w-8 text-white" />
                </div>
                <div>
                  <h1 className="text-2xl md:text-3xl font-bold text-slate-800 dark:text-slate-100">
                    Certificate of Achievement
                  </h1>
                  <p className="text-slate-500 dark:text-slate-400 text-sm mt-1">
                    Official Verification Document
                  </p>
                </div>
              </div>

              <Badge
                variant="outline"
                className="bg-emerald-50 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-300 border-emerald-200 dark:border-emerald-800 px-4 py-2 text-sm font-medium print:bg-white"
              >
                <CheckCircle2 className="h-4 w-4 mr-2" />
                Verified
              </Badge>
            </div>
          </CardHeader>

          <CardContent className="p-6 md:p-8">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
              {/* Certificate Details */}
              <div className="lg:col-span-2 space-y-6">
                {/* Title */}
                <motion.div
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ duration: 0.5, delay: 0.2 }}
                >
                  <h2 className="text-xl md:text-2xl font-semibold text-slate-800 dark:text-slate-100 mb-2">
                    {certificate.title}
                  </h2>
                  <p className="text-slate-600 dark:text-slate-300 text-sm">
                    {certificate.description || 'No description provided'}
                  </p>
                </motion.div>

                <Separator className="print:border-slate-300" />

                {/* Details Grid */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <motion.div
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ duration: 0.5, delay: 0.3 }}
                    className="flex items-start gap-3 p-3 bg-slate-50 dark:bg-slate-800/50 rounded-lg print:bg-slate-50"
                  >
                    <User className="h-5 w-5 text-slate-400 mt-0.5" />
                    <div>
                      <p className="text-xs text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                        Recipient
                      </p>
                      <p className="font-medium text-slate-800 dark:text-slate-200">
                        {certificate.student.name || 'Unknown'}
                      </p>
                      {certificate.student.degree && (
                        <p className="text-sm text-slate-500 dark:text-slate-400">
                          {certificate.student.degree}
                        </p>
                      )}
                      {certificate.student.college && (
                        <p className="text-sm text-slate-500 dark:text-slate-400">
                          {certificate.student.college}
                        </p>
                      )}
                    </div>
                  </motion.div>

                  <motion.div
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ duration: 0.5, delay: 0.35 }}
                    className="flex items-start gap-3 p-3 bg-slate-50 dark:bg-slate-800/50 rounded-lg print:bg-slate-50"
                  >
                    <Building2 className="h-5 w-5 text-slate-400 mt-0.5" />
                    <div>
                      <p className="text-xs text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                        Organization
                      </p>
                      <p className="font-medium text-slate-800 dark:text-slate-200">
                        {certificate.organization}
                      </p>
                    </div>
                  </motion.div>

                  <motion.div
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ duration: 0.5, delay: 0.4 }}
                    className="flex items-start gap-3 p-3 bg-slate-50 dark:bg-slate-800/50 rounded-lg print:bg-slate-50"
                  >
                    <Calendar className="h-5 w-5 text-slate-400 mt-0.5" />
                    <div>
                      <p className="text-xs text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                        Issue Date
                      </p>
                      <p className="font-medium text-slate-800 dark:text-slate-200">
                        {formatDate(certificate.issuedAt || certificate.verifiedAt)}
                      </p>
                    </div>
                  </motion.div>

                  <motion.div
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ duration: 0.5, delay: 0.45 }}
                    className="flex items-start gap-3 p-3 bg-slate-50 dark:bg-slate-800/50 rounded-lg print:bg-slate-50"
                  >
                    <ShieldCheck className="h-5 w-5 text-emerald-500 mt-0.5" />
                    <div>
                      <p className="text-xs text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                        Verified By
                      </p>
                      <p className="font-medium text-slate-800 dark:text-slate-200">
                        {certificate.verifier?.name || certificate.verifierEmail}
                      </p>
                    </div>
                  </motion.div>
                </div>

                {/* File Preview */}
                {certificate.fileUrl && (
                  <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.5, delay: 0.5 }}
                    className="mt-6"
                  >
                    <h3 className="text-sm font-medium text-slate-700 dark:text-slate-300 mb-3 flex items-center gap-2">
                      <FileText className="h-4 w-4" />
                      Certificate Document
                    </h3>
                    <div className="border border-slate-200 dark:border-slate-700 rounded-lg overflow-hidden bg-slate-50 dark:bg-slate-800/50 print:bg-white">
                      {isImageFile ? (
                        <div className="relative">
                          <img
                            src={certificate.fileUrl}
                            alt={certificate.fileName || 'Certificate'}
                            className="w-full h-auto max-h-96 object-contain"
                          />
                        </div>
                      ) : isPdfFile ? (
                        <div className="p-8 text-center">
                          <FileText className="h-12 w-12 text-slate-400 mx-auto mb-3" />
                          <p className="text-slate-600 dark:text-slate-300 font-medium mb-2">
                            {certificate.fileName || 'Certificate Document'}
                          </p>
                          <p className="text-sm text-slate-500 dark:text-slate-400 mb-4">
                            PDF Document
                          </p>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={handleDownloadFile}
                            className="print:hidden"
                          >
                            <ExternalLink className="h-4 w-4 mr-2" />
                            View PDF
                          </Button>
                        </div>
                      ) : (
                        <div className="p-8 text-center">
                          <FileText className="h-12 w-12 text-slate-400 mx-auto mb-3" />
                          <p className="text-slate-600 dark:text-slate-300 font-medium mb-2">
                            {certificate.fileName || 'Certificate Document'}
                          </p>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={handleDownloadFile}
                            className="print:hidden"
                          >
                            <Download className="h-4 w-4 mr-2" />
                            Download
                          </Button>
                        </div>
                      )}
                    </div>
                  </motion.div>
                )}

                {/* Verification Notice */}
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ duration: 0.5, delay: 0.6 }}
                  className="bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800 rounded-lg p-4 print:bg-emerald-50"
                >
                  <div className="flex items-start gap-3">
                    <ShieldCheck className="h-5 w-5 text-emerald-600 dark:text-emerald-400 mt-0.5" />
                    <div>
                      <p className="font-medium text-emerald-800 dark:text-emerald-200">
                        Verification Confirmed
                      </p>
                      <p className="text-sm text-emerald-700 dark:text-emerald-300 mt-1">
                        This certificate has been verified by {certificate.organization} on{' '}
                        {formatDate(certificate.verifiedAt)}. The authenticity of this document can be
                        confirmed by scanning the QR code or visiting the URL above.
                      </p>
                    </div>
                  </div>
                </motion.div>
              </div>

              {/* QR Code & Actions */}
              <div className="space-y-4 print:break-inside-avoid">
                <QRDisplay url={publicUrl} certificateTitle={certificate.title} />

                {/* Action Buttons */}
                <div className="flex flex-col gap-2 print:hidden">
                  <Button
                    variant="outline"
                    className="w-full justify-start"
                    onClick={handlePrint}
                  >
                    <Printer className="h-4 w-4 mr-2" />
                    Print Certificate
                  </Button>

                  {certificate.fileUrl && (
                    <Button
                      variant="outline"
                      className="w-full justify-start"
                      onClick={handleDownloadFile}
                    >
                      <Download className="h-4 w-4 mr-2" />
                      Download Document
                    </Button>
                  )}

                  {session?.user && (
                    <Dialog open={reportOpen} onOpenChange={setReportOpen}>
                      <DialogTrigger asChild>
                        <Button
                          variant="outline"
                          className="w-full justify-start text-destructive hover:text-destructive hover:bg-destructive/10"
                        >
                          <AlertTriangle className="h-4 w-4 mr-2" />
                          Report Abuse
                        </Button>
                      </DialogTrigger>
                      <DialogContent>
                        <DialogHeader>
                          <DialogTitle>Report Certificate</DialogTitle>
                          <DialogDescription>
                            If you believe this certificate is fraudulent or violates our terms of service, please provide a detailed reason below.
                          </DialogDescription>
                        </DialogHeader>
                        <div className="py-4">
                          <Label htmlFor="reason" className="mb-2 block">Reason for reporting</Label>
                          <textarea
                            id="reason"
                            placeholder="Please provide specific details..."
                            value={reportReason}
                            onChange={(e) => setReportReason(e.target.value)}
                            className="flex min-h-[100px] w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
                            disabled={reporting}
                          />
                        </div>
                        <DialogFooter>
                          <Button variant="outline" onClick={() => setReportOpen(false)} disabled={reporting}>
                            Cancel
                          </Button>
                          <Button variant="destructive" onClick={handleReportAbuse} disabled={reporting}>
                            {reporting ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : null}
                            Submit Report
                          </Button>
                        </DialogFooter>
                      </DialogContent>
                    </Dialog>
                  )}
                </div>

                {/* Certificate ID */}
                <div className="text-center p-3 bg-slate-50 dark:bg-slate-800/50 rounded-lg print:bg-slate-50">
                  <p className="text-xs text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-1">
                    Certificate ID
                  </p>
                  <p className="font-mono text-sm text-slate-700 dark:text-slate-300 break-all">
                    {certificate.publicLinkId}
                  </p>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </motion.div>
    </div>
  )
}
