import { Suspense } from "react";
import ScanForm from "./scan-form";
import TaskList from "./task-list";

export default function ScansPage() {
  return (
    <div className="page-container">
      <div className="page-head">
        <div>
          <h1 className="page-title">Scan Manager</h1>
          <p className="page-subtitle">
            Configure and launch network reconnaissance scans
          </p>
        </div>
      </div>

      <Suspense
        fallback={
          <div style={{ textAlign: "center", padding: 40, color: "var(--color-text-muted)" }}>
            Loading scan interface...
          </div>
        }
      >
        <ScanForm />
      </Suspense>

      <TaskList />
    </div>
  );
}
