import { Link } from "react-router-dom";
import { Compass } from "lucide-react";
import { Button, EmptyState } from "../components/ui";

export function NotFoundPage() {
  return (
    <div style={{ minHeight: "60vh", display: "flex", alignItems: "center", justifyContent: "center" }}>
      <div className="card" style={{ maxWidth: 460, width: "100%" }}>
        <EmptyState
          icon={Compass}
          title="404 · Página no encontrada"
          description="La ruta solicitada no existe o ha sido movida."
          action={<Link to="/"><Button variant="primary">Volver al panel</Button></Link>}
        />
      </div>
    </div>
  );
}
