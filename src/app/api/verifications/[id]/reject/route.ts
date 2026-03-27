import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { sendEmail } from '@/lib/mail';

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    const body = await request.json();
    const { verifierId, reason } = body;

    if (!verifierId) {
      return NextResponse.json(
        { error: 'Verifier ID is required' },
        { status: 400 }
      );
    }

    if (!reason || reason.trim() === '') {
      return NextResponse.json(
        { error: 'Rejection reason is required' },
        { status: 400 }
      );
    }

    // Check if certificate exists and is pending
    const certificate = await db.certificate.findUnique({
      where: { id },
    });

    if (!certificate) {
      return NextResponse.json(
        { error: 'Certificate not found' },
        { status: 404 }
      );
    }

    if (certificate.status !== 'pending') {
      return NextResponse.json(
        { error: 'Certificate is not pending verification' },
        { status: 400 }
      );
    }

    // Update certificate status
    const updatedCertificate = await db.certificate.update({
      where: { id },
      data: {
        status: 'rejected',
        verifierId,
        comments: reason,
        verifiedAt: new Date(),
      },
      include: {
        student: {
          select: {
            id: true,
            name: true,
            email: true,
          },
        },
        verifier: {
          select: {
            name: true,
            email: true,
          },
        },
      },
    });

    // Send email notification to student (Reject Flow)
    if (updatedCertificate.student.email) {
      const html = `
        <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
          <h2>Certificate Verification Update</h2>
          <p>Hello ${updatedCertificate.student.name || 'Student'},</p>
          <p>Your certificate <strong>"${updatedCertificate.title}"</strong> has been rejected by <strong>${updatedCertificate.verifier?.name || 'a Verifier'}</strong>.</p>
          <p>Status: <strong style="color: red;">REJECTED</strong></p>
          <p><strong>Reason:</strong> ${reason}</p>
          <p>Thanks,<br>CredCheck Team</p>
        </div>
      `;

      // Send email notification in background (Reject Flow)
      sendEmail({
        to: updatedCertificate.student.email,
        subject: `Certificate Rejected: ${updatedCertificate.title}`,
        html,
        replyTo: updatedCertificate.verifier?.email || undefined,
        senderName: `${updatedCertificate.verifier?.name || 'Verifier'} (Verifier)`
      }).catch(err => console.error("Background rejection email error:", err));
    }

    // Identify student and notify in background
    if (updatedCertificate.student.id) {
      db.notification.create({
        data: {
          userId: updatedCertificate.student.id,
          title: "Certificate Rejected",
          message: `Your certificate "${updatedCertificate.title}" was rejected by the verifier.`,
          type: "CERTIFICATE_REJECTED",
        }
      }).catch(err => console.error("Background rejection notification error:", err));
    }

    return NextResponse.json({
      success: true,
      certificate: updatedCertificate,
    });
  } catch (error) {
    console.error('Error rejecting certificate:', error);
    return NextResponse.json(
      { error: 'Failed to reject certificate' },
      { status: 500 }
    );
  }
}
