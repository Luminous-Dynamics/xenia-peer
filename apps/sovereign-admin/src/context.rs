use leptos::prelude::*;

use crate::auth::AuthState;
use crate::config::DaemonConfig;

pub fn missing_context_view(name: &'static str) -> impl IntoView {
    view! {
        <main class="app-error">
            <section class="error-card">
                <h1>"Application context unavailable"</h1>
                <p>
                    "The admin console could not access required application context: "
                    <code>{name}</code>
                    "."
                </p>
                <p>"Reload the page. If this persists, check the app root providers."</p>
            </section>
        </main>
    }
}

pub fn auth_context() -> Result<AuthState, impl IntoView> {
    use_context::<AuthState>().ok_or_else(|| missing_context_view("AuthState"))
}

pub fn daemon_config_context() -> Result<DaemonConfig, impl IntoView> {
    use_context::<DaemonConfig>().ok_or_else(|| missing_context_view("DaemonConfig"))
}
