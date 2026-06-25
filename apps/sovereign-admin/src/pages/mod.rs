// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

mod consent;
mod devices;
mod governance;
mod login;
mod monitor;
mod policy;
mod sessions;

pub use consent::ConsentModal;
pub use devices::DevicesPage;
pub use governance::GovernancePage;
pub use login::LoginPage;
pub use monitor::MonitorPage;
pub use policy::PolicyPage;
pub use sessions::SessionsPage;
