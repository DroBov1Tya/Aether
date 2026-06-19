import Link from 'next/link';

export default function NotFound() {
  return (
    <div className="flex h-[70vh] items-center justify-center">
      <div className="text-center">
        <div className="mb-6 font-display text-[120px] font-black leading-none holo-text">
          404
        </div>
        <h1 className="mb-3 text-2xl font-semibold text-white">Host not found</h1>
        <p className="mb-8 text-secondary">The host you're looking for doesn't exist or hasn't been scanned yet.</p>
        <Link href="/" className="inline-block rounded-md bg-emerald px-6 py-3 text-sm font-semibold text-white transition-all hover:-translate-y-0.5">
          ← Back to Home
        </Link>
      </div>
    </div>
  );
}
