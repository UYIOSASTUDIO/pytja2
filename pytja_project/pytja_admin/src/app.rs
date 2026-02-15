use crate::network::AdminClient;
// FIX: MountInfo importiert
use pytja_proto::pytja::{SessionInfo, RoleInfo, MountInfo};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CurrentTab {
    Dashboard,
    Sessions,
    Roles,
    Databases, // Tab 4
}

#[derive(Clone, Copy, PartialEq)]
pub enum PopupType {
    None,
    UserActions,
    ChangeRoleInput,
    AddDbInput,
}

pub struct App {
    pub client: AdminClient,
    pub current_tab: CurrentTab,

    // Data Lists
    pub sessions: Vec<SessionInfo>,
    pub selected_session_index: usize,

    pub roles: Vec<RoleInfo>,

    // FIX: Mounts Feld hinzugefügt
    pub mounts: Vec<MountInfo>,

    // UI State
    pub active_popup: PopupType,
    // FIX: Input Buffer hinzugefügt
    pub input_buffer: String,

    pub status_message: String,
    pub total_active: i32,
    pub should_quit: bool,
}

impl App {
    pub fn new(client: AdminClient) -> Self {
        Self {
            client,
            current_tab: CurrentTab::Dashboard,
            sessions: vec![],
            selected_session_index: 0,
            roles: vec![],
            // FIX: Initialisierung der neuen Felder
            mounts: vec![],
            active_popup: PopupType::None,
            input_buffer: String::new(),
            status_message: "Ready.".to_string(),
            total_active: 0,
            should_quit: false,
        }
    }

    pub async fn refresh_data(&mut self) {
        self.status_message = "Refreshing...".to_string();

        // 1. Sessions laden
        match self.client.get_sessions().await {
            Ok((s, total)) => {
                self.sessions = s;
                self.total_active = total;
            },
            Err(e) => self.status_message = format!("Error Sessions: {}", e),
        }

        // 2. Rollen laden
        match self.client.list_roles().await {
            Ok(r) => self.roles = r,
            Err(e) => self.status_message = format!("Error Roles: {}", e),
        }

        // 3. Mounts laden (NEU)
        match self.client.get_mounts().await {
            Ok(m) => self.mounts = m,
            Err(e) => self.status_message = format!("Error Mounts: {}", e),
        }

        if self.status_message == "Refreshing..." {
            self.status_message = "Data updated.".to_string();
        }
    }

    pub fn next_tab(&mut self) {
        self.current_tab = match self.current_tab {
            CurrentTab::Dashboard => CurrentTab::Sessions,
            CurrentTab::Sessions => CurrentTab::Roles,
            CurrentTab::Roles => CurrentTab::Databases, // FIX: Logic erweitert
            CurrentTab::Databases => CurrentTab::Dashboard,
        };
    }

    pub fn next_row(&mut self) {
        if self.current_tab == CurrentTab::Sessions && !self.sessions.is_empty() {
            if self.selected_session_index < self.sessions.len() - 1 {
                self.selected_session_index += 1;
            } else {
                self.selected_session_index = 0;
            }
        }
    }

    pub fn previous_row(&mut self) {
        if self.current_tab == CurrentTab::Sessions && !self.sessions.is_empty() {
            if self.selected_session_index > 0 {
                self.selected_session_index -= 1;
            } else {
                self.selected_session_index = self.sessions.len() - 1;
            }
        }
    }
}