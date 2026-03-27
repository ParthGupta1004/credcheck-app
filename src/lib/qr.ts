import QRCode from 'qrcode';
import os from 'os';

/**
 * Gets the local IPv4 address of the machine for development connectivity.
 * Falls back to 'localhost' if no external interface is found.
 */
function getLocalIp(): string {
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    const networkInterface = interfaces[name];
    if (networkInterface) {
      for (const iface of networkInterface) {
        // Skip over non-IPv4 and internal (loopback) addresses
        if (iface.family === 'IPv4' && !iface.internal) {
          return iface.address;
        }
      }
    }
  }
  return 'localhost';
}

export async function generateQRCode(data: string): Promise<string> {
  try {
    const qrDataUrl = await QRCode.toDataURL(data, {
      width: 300,
      margin: 2,
      color: {
        dark: '#000000',
        light: '#ffffff',
      },
    });
    return qrDataUrl;
  } catch (error) {
    console.error('Error generating QR code:', error);
    throw error;
  }
}

export function getPublicCertificateUrl(publicLinkId: string): string {
  let baseUrl = process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000';
  
  // If we're in development and using localhost, try to swap it for the local IP
  // so mobile devices on the same WiFi can scan the QR code.
  if (baseUrl.includes('localhost') || baseUrl.includes('127.0.0.1')) {
    const localIp = getLocalIp();
    if (localIp !== 'localhost') {
      baseUrl = baseUrl.replace('localhost', localIp).replace('127.0.0.1', localIp);
    }
  }
  
  return `${baseUrl}/cert/${publicLinkId}`;
}
