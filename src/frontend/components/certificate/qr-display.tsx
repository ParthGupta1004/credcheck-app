'use client'

import { useEffect, useRef, useState } from 'react'
import QRCode from 'qrcode'
import { motion } from 'framer-motion'
import { Card, CardContent } from '@/components/ui/card'
import { Download, Share2 } from 'lucide-react'
import { Button } from '@/components/ui/button'

interface QRDisplayProps {
  url: string
  certificateTitle: string
}

export function QRDisplay({ url, certificateTitle }: QRDisplayProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const [qrDataUrl, setQrDataUrl] = useState<string>('')
  const [isLoaded, setIsLoaded] = useState(false)

  useEffect(() => {
    const generateQR = async () => {
      if (canvasRef.current) {
        try {
          await QRCode.toCanvas(canvasRef.current, url, {
            width: 200,
            margin: 2,
            color: {
              dark: '#1e293b',
              light: '#ffffff',
            },
          })

          // Also generate as data URL for download
          const dataUrl = await QRCode.toDataURL(url, {
            width: 400,
            margin: 2,
            color: {
              dark: '#1e293b',
              light: '#ffffff',
            },
          })
          setQrDataUrl(dataUrl)
          setIsLoaded(true)
        } catch (error) {
          console.error('Error generating QR code:', error)
        }
      }
    }

    generateQR()
  }, [url])

  const handleDownloadQR = () => {
    if (qrDataUrl) {
      const link = document.createElement('a')
      link.download = `${certificateTitle.replace(/\s+/g, '-').toLowerCase()}-qr.png`
      link.href = qrDataUrl
      link.click()
    }
  }

  const handleShare = async () => {
    if (navigator.share) {
      try {
        await navigator.share({
          title: `Certificate: ${certificateTitle}`,
          url: url,
        })
      } catch (error) {
        console.log('Share cancelled')
      }
    } else {
      // Fallback: copy to clipboard
      await navigator.clipboard.writeText(url)
      alert('Link copied to clipboard!')
    }
  }

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.9 }}
      animate={{ opacity: isLoaded ? 1 : 0, scale: isLoaded ? 1 : 0.9 }}
      transition={{ duration: 0.5, ease: 'easeOut' }}
    >
      <Card className="overflow-hidden border-2 border-slate-200 dark:border-slate-700 shadow-lg">
        <CardContent className="p-6">
          <div className="flex flex-col items-center gap-4">
            <div className="relative">
              <div className="absolute inset-0 bg-gradient-to-br from-emerald-400/20 to-teal-400/20 rounded-lg blur-xl" />
              <div className="relative bg-white p-3 rounded-lg shadow-inner">
                <canvas
                  ref={canvasRef}
                  className="block"
                  aria-label="QR Code for certificate verification"
                />
              </div>
            </div>

            <p className="text-sm text-muted-foreground text-center max-w-[200px]">
              Scan to verify this certificate
            </p>

            <div className="flex gap-2 w-full">
              <Button
                variant="outline"
                size="sm"
                className="flex-1"
                onClick={handleDownloadQR}
                disabled={!qrDataUrl}
              >
                <Download className="h-4 w-4 mr-1" />
                QR
              </Button>
              <Button
                variant="outline"
                size="sm"
                className="flex-1"
                onClick={handleShare}
              >
                <Share2 className="h-4 w-4 mr-1" />
                Share
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  )
}
