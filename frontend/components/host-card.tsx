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
    <Link href={`/host/${host.target}`} className="host-card">
      <div className="mb-3 flex items-center gap-2">
        <div className="h-2 w-2 rounded-full bg-[#5fed83]" />
        <span className="font-mono text-base font-medium text-white">
          {host.target}
        </span>
      </div>

      <div className="mb-3 flex flex-wrap gap-1.5">
        {techs.map((t) => (
          <span
            key={t}
            className="rounded-full border border-[#21262d] bg-[#283041] px-2.5 py-1 text-[11px] text-white"
          >
            {t}
          </span>
        ))}
      </div>

      <div className="border-t border-[#21262d] pt-3">
        <span className="text-[13px] font-medium text-[#8dd6ff]">
          View Details →
        </span>
      </div>
    </Link>
  );
}
