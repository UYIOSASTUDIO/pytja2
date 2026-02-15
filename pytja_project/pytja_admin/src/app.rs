use crate::network::AdminClient;
use pytja_proto::pytja::{SessionInfo, RoleInfo};

// FIX: Derive Copy & Clone hinzugefügt, damit wir das Enum einfach nutzen können
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CurrentTab {
    Dashboard,
    Sessions,
    Roles,
    Databases,
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

    // Listen-Navigation
    pub sessions: Vec<SessionInfo>,
    pub selected_session_index: usize, // NEU: Welcher User ist markiert?

    pub roles: Vec<RoleInfo>,

    // Popup State
    pub active_popup: PopupType, // NEU

    pub status_message: String,
    pub total_active: i32,
    pub should_quit: bool,

    pub mounts: Vec<MountInfo>,
    pub input_buffer: String,
}

impl App {
    pub fn new(client: AdminClient) -> Self {
        Self {
            client,
            current_tab: CurrentTab::Dashboard,
            sessions: vec![],
            selected_session_index: 0, // Init
            roles: vec![],
            active_popup: PopupType::None, // Init
            status_message: "Ready.".to_string(),
            total_active: 0,
            should_quit: false,
        }
    }

    // Navigation Helper
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

    pub async fn refresh_data(&mut self) {
        self.status_message = "Refreshing...".to_string();

        match self.client.get_sessions().await {
            Ok((s, total)) => {
                self.sessions = s;
                self.total_active = total;
            },
            Err(e) => self.status_message = format!("Error Sessions: {}", e),
        }

        match self.client.list_roles().await {
            Ok(r) => self.roles = r,
            Err(e) => self.status_message = format!("Error Roles: {}", e),
        }

        if self.status_message == "Refreshing..." {
            self.status_message = "Data updated.".to_string();
        }
    }

    pub fn next_tab(&mut self) {
        self.current_tab = match self.current_tab {
            CurrentTab::Dashboard => CurrentTab::Sessions,
            CurrentTab::Sessions => CurrentTab::Roles,
            CurrentTab::Roles => CurrentTab::Dashboard,
        };
    }
}