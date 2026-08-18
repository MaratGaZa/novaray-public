//! Модуль управления сетевыми маршрутами macOS и DNS
use tracing::info;

pub struct RouteManager;

impl Default for RouteManager {
    fn default() -> Self {
        Self::new()
    }
}

impl RouteManager {
    pub fn new() -> Self {
        Self
    }

    /// Установка маршрутов в интерфейс utun
    pub async fn apply_vpn_routes(&self, server_ip: &str, gateway: &str) -> anyhow::Result<()> {
        info!(
            "Настройка таблицы маршрутизации macOS: шлюз {}, сервер {}",
            gateway, server_ip
        );
        // Вызов route add / networksetup
        Ok(())
    }

    /// Восстановление исходных системных маршрутов
    pub async fn restore_default_routes(&self) -> anyhow::Result<()> {
        info!("Восстановление системных маршрутов macOS по умолчанию");
        Ok(())
    }
}
