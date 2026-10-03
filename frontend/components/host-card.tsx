import Link from "next/link";

interface Props {
  host: {
    target: string;
    technologies: string[];
  };
}

export default function HostCard({ host }: Props) {
  const techs = host.technologies.slice(0, 3);

  return (
    <Link
      href={`/host/${encodeURIComponent(host.target)}`}
      className="host-card"
    >
      <div className="mb-3 flex items-center gap-2">
        <div className="h-2 w-2 rounded-full bg-[#f6d9a6]" style={{ boxShadow: "0 0 8px rgba(246, 217, 166,0.6)" }} />
        <span className="font-mono text-base font-medium text-white">
          {host.target}
        </span>
      </div>

      <div className="mb-3 flex-wrap gap-1.5">
        {techs.map((t) => (
          <span key={t} className="tech-badge">
            {t}
          </span>
        ))}
      </div>

      <div className="border-t border-[#1b1a1e] pt-3">
        <span className="text-[13px] font-medium text-[#d3bda3]">
          View Details →
        </span>
      </div>
    </Link>
  );
}
