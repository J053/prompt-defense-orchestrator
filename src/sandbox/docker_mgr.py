"""
Módulo de Gestión de Infraestructura y Protocolo Pristine Docker Reset.
Incluye Auto-Detección: Contenedores Docker reales si el daemon está activo,
o Sandbox Local Determinista si Docker no está disponible en la máquina.
"""
import asyncio
import time
from typing import Dict, Any


class DockerManager:
    """Gestiona el ciclo de vida inmutable de las aplicaciones web objetivo."""

    def __init__(self):
        self.is_docker_available = False
        self.client = None

        try:
            import docker
            self.client = docker.from_env()
            self.client.ping()
            self.is_docker_available = True
            print("[+] Docker Daemon detectado y activo. Modo: Pristine Docker Real.")
        except Exception:
            self.is_docker_available = False
            self.client = None
            print("[!] Docker no disponible en este entorno. Activando: Local Deterministic Sandbox (Fallback).")

        self.targets: Dict[str, Dict[str, Any]] = {
            'DVWA': {
                'image': 'vulnerables/web-dvwa:latest',
                'ports': {'80/tcp': 8080},
                'endpoint': 'http://localhost:8080'
            },
            'WAVSEP': {
                'image': 'owasp/wavsep:latest',
                'ports': {'8080/tcp': 8081},
                'endpoint': 'http://localhost:8081'
            },
            'WackoPicko': {
                'image': 'adamdoupe/wackopicko:latest',
                'ports': {'80/tcp': 8082},
                'endpoint': 'http://localhost:8082'
            }
        }

        # Estado simulado inmutable para el Sandbox local
        self._sandbox_state = {app: {"status": "pristine", "resets": 0} for app in self.targets}

    def _sync_reset_container(self, app_name: str) -> Dict[str, Any]:
        """Ejecuta la destrucción y recreación limpia del contenedor."""
        if app_name not in self.targets:
            raise ValueError(f"Aplicación objetivo no reconocida: {app_name}")

        app_config = self.targets[app_name]

        if self.is_docker_available and self.client:
            image_name = app_config['image']
            for container in self.client.containers.list(all=True):
                if container.image.tags and image_name in container.image.tags[0]:
                    try:
                        container.stop(timeout=2)
                        container.remove(force=True)
                    except Exception:
                        pass

            container = self.client.containers.run(
                image_name, detach=True, ports=app_config['ports']
            )
            time.sleep(2)
            return {"status": "recreated", "id": container.id, "app": app_name}
        else:
            # Emulación determinista del Sandbox local
            self._sandbox_state[app_name]["resets"] += 1
            self._sandbox_state[app_name]["status"] = "pristine"
            time.sleep(0.01)  # Simulación de latencia de red limpia
            return {
                "status": "emulated_pristine",
                "app": app_name,
                "resets": self._sandbox_state[app_name]["resets"]
            }

    async def reset_container_async(self, app_name: str) -> Dict[str, Any]:
        """Ejecución asíncrona del protocolo Pristine Reset en un hilo secundario."""
        return await asyncio.to_thread(self._sync_reset_container, app_name)

    def prune_system(self) -> None:
        """Limpia los contenedores y recursos huérfanos al finalizar la prueba."""
        if self.is_docker_available and self.client:
            try:
                self.client.containers.prune()
            except Exception:
                pass
