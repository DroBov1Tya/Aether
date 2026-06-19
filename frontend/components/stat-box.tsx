export default function StatBox({
  label,
  value,
}: {
  label: string;
  value: string;
}) {
  return (
    <div className="stat-box">
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}
