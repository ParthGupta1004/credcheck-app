import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { sendEmail } from '@/lib/mail';

// GET - Fetch all certificates for a student
export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const studentId = searchParams.get('studentId');

    if (!studentId) {
      return NextResponse.json(
        { error: 'Student ID is required' },
        { status: 400 }
      );
    }

    const certificates = await db.certificate.findMany({
      where: { studentId },
      orderBy: { createdAt: 'desc' },
    });

    return NextResponse.json(certificates);
  } catch (error) {
    console.error('Error fetching certificates:', error);
    return NextResponse.json(
      { error: 'Failed to fetch certificates' },
      { status: 500 }
    );
  }
}

// POST - Create a new certificate
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { studentId, title, organization, description, verifierEmail, fileUrl, fileName } = body;

    if (!studentId || !title || !organization || !verifierEmail) {
      return NextResponse.json(
        { error: 'Missing required fields' },
        { status: 400 }
      );
    }

    // Note: publicLinkId and QR code will be generated when certificate is APPROVED
    // This ensures the link proves the certificate is verified
    // Both are set to null initially - each certificate gets unique link & QR at approval

    const certificate = await db.certificate.create({
      data: {
        studentId,
        title,
        organization,
        description: description || null,
        verifierEmail,
        fileUrl: fileUrl || null,
        fileName: fileName || null,
        publicLinkId: null, // Will be generated at approval time
        qrCodeUrl: null, // Will be generated at approval time
        status: 'pending',
      },
      include: {
        student: {
          select: {
            name: true,
            email: true,
          }
        }
      }
    });
    // Send email to verifier (Upload Action)
    if (certificate.student?.name) {
      const html = `
        <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
          <h2>New Certificate Verification Request</h2>
          <p>Hello,</p>
          <p><strong>${certificate.student.name}</strong> has uploaded a new certificate titled <strong>"${title}"</strong> and requested you to verify it.</p>
          <p><strong>Organization:</strong> ${organization}</p>
          <p>Please log in to your CredCheck Verifier Dashboard to review, approve, or reject this request.</p>
          <p>
            <a href="${process.env.NEXTAUTH_URL || 'http://localhost:3000'}/login" style="display:inline-block; padding: 10px 20px; background-color: #f59e0b; color: white; text-decoration: none; border-radius: 5px;">Go to Dashboard</a>
          </p>
          <br>
          <p>Thanks,<br>CredCheck Team</p>
        </div>
      `;

      // Send email in background (Upload Action)
      sendEmail({
        to: verifierEmail,
        subject: `New Verification Request: ${title}`,
        html,
        replyTo: certificate.student.email || undefined,
        senderName: `${certificate.student.name} (Student)`
      }).catch(err => console.error("Background email error:", err));
    }

    const cleanEmail = verifierEmail.trim().toLowerCase();

    // Identify verifier and send in-app notification in background
    const verifierUser = await db.user.findUnique({
      where: { email: cleanEmail },
    });

    if (verifierUser) {
      db.notification.create({
        data: {
          userId: verifierUser.id,
          title: "New Verification Request",
          message: `${certificate.student?.name || 'A student'} has uploaded "${title}" for your review.`,
          type: "CERTIFICATE_SUBMITTED",
        }
      }).catch(err => console.error("Background notification error:", err));
    }

    return NextResponse.json({
      success: true,
      certificate: certificate
    }, { status: 201 });
  } catch (error) {
    console.error('Error creating certificate:', error);
    return NextResponse.json(
      { error: 'Failed to create certificate' },
      { status: 500 }
    );
  }
}
