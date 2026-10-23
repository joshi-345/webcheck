import { NextRequest, NextResponse } from 'next/server';
import { runScan } from '@/utils/scanner';

export async function POST(req: NextRequest) {
  try {
    const { url } = await req.json();

    if (!url) {
      return NextResponse.json({ error: 'URL is required' }, { status: 400 });
    }

    const results = await runScan(url);
    return NextResponse.json(results, { status: 200 });
  } catch (error: any) {
    console.error("Scan Error:", error);
    return NextResponse.json({ error: 'Failed to run scan. Ensure it is a valid public URL.' }, { status: 500 });
  }
}
