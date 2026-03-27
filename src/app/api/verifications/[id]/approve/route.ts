import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { v4 as uuidv4 } from 'uuid';
import { generateQRCode, getPublicCertificateUrl } from '@/lib/qr';
import { sendEmail } from '@/lib/mail';

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    const body = await request.json();
    const { verifierId, comments } = body;

    if (!verifierId) {
      return NextResponse.json(
        { error: 'Verifier ID is required' },
        { status: 400 }
      );
    }

    // Check if certificate exists and is pending
    const certificate = await db.certificate.findUnique({
      where: { id },
      include: {
        student: {
          select: {
            name: true,
            email: true,
          }
        }
      }
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

    // Generate public link ID and QR code NOW (at approval time)
    // This ensures both the link and QR prove the certificate is verified
    const publicLinkId = uuidv4();
    const publicUrl = getPublicCertificateUrl(publicLinkId);
    
    // Generate QR code from the public URL
    const qrCodeUrl = await generateQRCode(publicUrl);

    // Update certificate status with public link and QR code
    const updatedCertificate = await db.certificate.update({
      where: { id },
      data: {
        status: 'verified',
        verifierId,
        comments: comments || null,
        verifiedAt: new Date(),
        issuedAt: certificate.issuedAt || new Date(),
        publicLinkId, // Set public link at approval time
        qrCodeUrl, // Set QR code at approval time
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


    // Send email notification to student (Approve Flow)
    if (updatedCertificate.student.email) {
      let html = `
        <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
          <h2>Certificate Verification Update</h2>
          <p>Hello ${updatedCertificate.student.name || 'Student'},</p>
          <p>Your certificate <strong>"${updatedCertificate.title}"</strong> has been approved by <strong>${updatedCertificate.verifier?.name || 'a Verifier'}</strong>.</p>
          <p>Status: <strong style="color: green;">APPROVED</strong></p>
      `;
      if (comments) {
        html += `<p><strong>Comments:</strong> ${comments}</p>`;
      }
      html += `
          <p>Your certificate is now publicly verifiable. You can view or share the link below:</p>
          <p><a href="${publicUrl}" style="display:inline-block; padding: 10px 20px; background-color: #10b981; color: white; text-decoration: none; border-radius: 5px;">View Verified Certificate</a></p>
      `;
      
      const attachments: any[] = [];
      if (qrCodeUrl && qrCodeUrl.startsWith('data:image')) {
        html += `
          <p>Or scan this QR Code:</p>
          <p><img src="cid:qrcode-attachment" alt="QR Code" width="200" /></p>
        `;
        attachments.push({
          filename: 'qrcode.png',
          content: qrCodeUrl.split('base64,')[1],
          encoding: 'base64',
          cid: 'qrcode-attachment'
        });
      }
      
      html += `
          <p>Thanks,<br>CredCheck Team</p>
        </div>
      `;

      // Send email notification in background (Approve Flow)
      sendEmail({
        to: updatedCertificate.student.email,
        subject: `Certificate Approved: ${updatedCertificate.title}`,
        html,
        replyTo: updatedCertificate.verifier?.email || undefined,
        senderName: `${updatedCertificate.verifier?.name || 'Verifier'} (Verifier)`,
        attachments: attachments.length > 0 ? attachments : undefined
      }).catch(err => console.error("Background approval email error:", err));
    }

    // Identify student and notify in background
    if (updatedCertificate.student.id) {
      db.notification.create({
        data: {
          userId: updatedCertificate.student.id,
          title: "Certificate Approved",
          message: `Your certificate "${updatedCertificate.title}" has been approved!`,
          type: "CERTIFICATE_APPROVED",
        }
      }).catch(err => console.error("Background approval notification error:", err));
    }

    return NextResponse.json({
      success: true,
      certificate: updatedCertificate,
      publicUrl, // Return public URL for sharing
    });
  } catch (error) {
    console.error('Error approving certificate:', error);
    return NextResponse.json(
      { error: 'Failed to approve certificate' },
      { status: 500 }
    );
  }
}
