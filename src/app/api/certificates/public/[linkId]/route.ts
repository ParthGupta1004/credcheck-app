import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/lib/db'

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ linkId: string }> }
) {
  try {
    const { linkId } = await params

    if (!linkId) {
      return NextResponse.json(
        { error: 'Invalid certificate link' },
        { status: 400 }
      )
    }

    const certificate = await db.certificate.findUnique({
      where: { publicLinkId: linkId },
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
      return NextResponse.json(
        { error: 'Certificate not found' },
        { status: 404 }
      )
    }

    // Only return verified certificates publicly
    if (certificate.status !== 'verified') {
      return NextResponse.json(
        { error: 'Certificate is not verified', status: certificate.status },
        { status: 403 }
      )
    }

    // Return certificate data (read-only, secure)
    return NextResponse.json({
      certificate: {
        id: certificate.id,
        title: certificate.title,
        organization: certificate.organization,
        description: certificate.description,
        fileUrl: certificate.fileUrl,
        fileName: certificate.fileName,
        status: certificate.status,
        issuedAt: certificate.issuedAt,
        verifiedAt: certificate.verifiedAt,
        publicLinkId: certificate.publicLinkId,
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
    })
  } catch (error) {
    console.error('Error fetching certificate:', error)
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
}
