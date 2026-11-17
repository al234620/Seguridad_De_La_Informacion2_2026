from flask import Flask, g, render_template
from werkzeug.exceptions import HTTPException

from . import bitacora, db, seguridad
from .config import configuracion_por_defecto


def dinero(centavos):
    return f"${centavos / 100:,.2f} MXN"


def create_app(sobrescribir: dict | None = None):
    app = Flask(__name__)
    app.config.update(configuracion_por_defecto())
    if sobrescribir:
        app.config.update(sobrescribir)

    app.secret_key = app.config["FLASK_KEY_PATH"].read_bytes()
    app.config["PROPAGATE_EXCEPTIONS"] = False
    app.debug = False  # nunca mostrar trazas al usuario

    bitacora.configurar_log_archivo(app)
    app.teardown_appcontext(db.close_db)
    app.jinja_env.filters["dinero"] = dinero
    app.jinja_env.globals["csrf_token"] = seguridad.csrf_token

    @app.before_request
    def _antes():
        seguridad.cargar_usuario()
        seguridad.verificar_csrf()

    app.after_request(seguridad.cabeceras_seguras)

    from .rutas_admin import bp as admin_bp
    from .rutas_cliente import bp as cliente_bp
    from .rutas_operador import bp as operador_bp
    from .rutas_publicas import bp as publico_bp
    app.register_blueprint(publico_bp)
    app.register_blueprint(cliente_bp)
    app.register_blueprint(operador_bp, url_prefix="/operador")
    app.register_blueprint(admin_bp, url_prefix="/admin")

    mensajes = {
        400: "Solicitud inválida.",
        401: "Debes iniciar sesión para continuar.",
        403: "No tienes permiso para realizar esta acción.",
        404: "El recurso no existe.",
        413: "El archivo excede el tamaño permitido.",
        500: "Ocurrió un error interno. El incidente quedó registrado.",
    }

    def _error(codigo):
        def manejador(e):
            if codigo == 500:
                app.logger.exception("Error interno")
                try:
                    bitacora.registrar("INTERNAL_ERROR", "ERROR", user_id=g.get("user") and g.user["id"],
                                       details=type(getattr(e, "original_exception", e)).__name__)
                except Exception:
                    pass
            return render_template("error.html", codigo=codigo, mensaje=mensajes[codigo]), codigo
        return manejador

    for c in mensajes:
        app.register_error_handler(c, _error(c))

    def _otro(e):
        if isinstance(e, HTTPException):
            return render_template("error.html", codigo=e.code, mensaje="Solicitud no válida."), e.code
        return _error(500)(e)

    app.register_error_handler(Exception, _otro)
    return app
