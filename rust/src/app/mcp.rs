use super::*;

impl ClumsyMagiApp {
    pub(super) fn ui_mcp_section(&mut self, ui: &mut egui::Ui) {
        ui.group(|ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("MCP Automation").strong());
                let active = self.mcp.is_some();
                ui.colored_label(
                    if active {
                        ok_color(ui)
                    } else {
                        ui.visuals().weak_text_color()
                    },
                    if active { "Running" } else { "Off" },
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .add_enabled(
                            active,
                            egui::Button::new(
                                if self
                                    .mcp_copied_at
                                    .is_some_and(|t| t.elapsed() < Duration::from_secs(2))
                                {
                                    "Copied!"
                                } else {
                                    "Copy Config"
                                },
                            ),
                        )
                        .clicked()
                    {
                        match self.mcp.as_ref().unwrap().client_config() {
                            Ok(text) => {
                                ui.ctx().copy_text(text);
                                self.mcp_copied_at = Some(Instant::now());
                            }
                            Err(e) => self.mcp_error = Some(e),
                        }
                    }
                    if ui
                        .button(if active { "Disable" } else { "Enable" })
                        .clicked()
                    {
                        self.mcp_error = None;
                        self.mcp_copied_at = None;
                        if active {
                            self.mcp.take();
                            if self.mcp_started {
                                self.stop_filtering();
                            }
                        } else {
                            let token = if self.config.mcp_token.is_empty() {
                                crate::mcp::new_token()
                            } else {
                                Ok(self.config.mcp_token.clone())
                            };
                            match token.and_then(|token| {
                                let host = if self.config.mcp_lan {
                                    self.config.mcp_host.parse::<std::net::Ipv4Addr>()
                                        .map_err(|_| "Enter the Windows LAN IPv4 address".to_string())?
                                } else { std::net::Ipv4Addr::LOCALHOST };
                                crate::mcp::Server::start(self.config.mcp_port, token, self.config.mcp_lan, host)
                            }) {
                                Ok(server) => {
                                    self.config.mcp_port = server.port;
                                    self.config.mcp_token = server.token.clone();
                                    self.mcp = Some(server);
                                    self.mark_dirty();
                                    // Reopen capture so an existing manual run also excludes the control connection.
                                    if self.engine.as_ref().is_some_and(|engine| engine.is_running()) {
                                        self.restart_filtering();
                                    }
                                }
                                Err(e) => self.mcp_error = Some(e),
                            }
                        }
                    }
                });
            });
            ui.horizontal(|ui| {
                ui.add_enabled_ui(self.mcp.is_none(), |ui| {
                    if ui.selectable_value(&mut self.config.mcp_lan, false, "This PC").changed() { self.mark_dirty(); }
                    if ui.selectable_value(&mut self.config.mcp_lan, true, "LAN / VPN").changed() { self.mark_dirty(); }
                    ui.separator();
                    ui.label("Port");
                    if ui.add(egui::DragValue::new(&mut self.config.mcp_port).range(1024..=65535)).changed() { self.mark_dirty(); }
                });
            });
            if self.config.mcp_lan {
                ui.horizontal(|ui| {
                    ui.label("Windows IP");
                    ui.add_enabled_ui(self.mcp.is_none(), |ui| {
                        if ui.add(egui::TextEdit::singleline(&mut self.config.mcp_host).desired_width(140.0).hint_text("LAN IPv4 address")).changed() { self.mark_dirty(); }
                        if ui.button("Detect").clicked() {
                            match crate::mcp::detect_lan_host() {
                                Some(host) => { self.config.mcp_host = host.to_string(); self.mark_dirty(); self.mcp_error = None; }
                                None => self.mcp_error = Some("Could not detect an address. Enter the Windows LAN or VPN IPv4 address.".into()),
                            }
                        }
                    });
                });
                ui.label(egui::RichText::new("HTTP on trusted LAN / VPN only. Access token required.").small().weak());
            }
            if let Some(server) = &self.mcp {
                ui.monospace(server.endpoint());
                ui.label(egui::RichText::new("MCP TCP port is excluded from capture.").small().weak());
            }
            if let Some(e) = &self.mcp_error {
                ui.colored_label(error_color(ui), e);
            }
            if self.mcp.is_some() {
                ui.label(
                    egui::RichText::new(
                        "Copy to your Mac MCP client. Keep this window open.",
                    )
                    .small()
                    .weak(),
                );
            }
        });
    }

    pub(super) fn poll_mcp(&mut self) {
        if self.mcp.as_ref().is_some_and(|server| !server.is_running()) {
            self.mcp.take();
            self.mcp_error = Some("MCP listener stopped. Enable it to reconnect.".into());
            if self.mcp_started {
                self.stop_filtering();
            }
        }
        // Execute on the UI thread so GUI and MCP mutations have a single owner.
        for _ in 0..8 {
            let command = self.mcp.as_ref().and_then(|s| s.commands.try_recv().ok());
            let Some(command) = command else {
                break;
            };
            if Instant::now() >= command.expires {
                continue;
            }
            let response =
                crate::mcp::dispatch(command.request, |name, args| self.mcp_tool(name, args));
            let _ = command.reply.send(response);
        }
    }

    fn mcp_tool(
        &mut self,
        name: &str,
        args: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        use serde_json::json;
        let running = self.engine.as_ref().is_some_and(|e| e.is_running());
        match name {
            "get_status" => {
                let mut config = self.config.clone();
                config.sync_from_params(&self.params);
                Ok(
                    json!({"running":running,"filter":config.filter,"capture_filter":self.mcp.as_ref().map(|server|crate::mcp::capture_filter(&config.filter,server.port)),"modules":config.modules,"target_pid":self.target_pid,
                    "driver_available":self.lib.is_some(),"elevated":self.elevated,"status":self.status,
                    "remaining_secs":self.engine.as_ref().filter(|e| e.is_running()).map(|e| e.deadline().saturating_duration_since(Instant::now()).as_secs())}),
                )
            }
            "get_stats" => {
                let s = self
                    .engine
                    .as_ref()
                    .map(|e| e.shared.stats.snapshot())
                    .unwrap_or(self.final_stats);
                Ok(
                    json!({"captured":s.captured,"sent":s.sent,"dropped":s.dropped,"modified":s.modified,"send_failed":s.send_failed}),
                )
            }
            "get_logs" => {
                let logs = self
                    .engine
                    .as_ref()
                    .map(|e| e.shared.log.snapshot())
                    .unwrap_or_else(|| self.log_cache.clone());
                // Bound the bridge response independently of the engine's log capacity.
                Ok(json!(logs.iter().rev().take(100).collect::<Vec<_>>().into_iter().rev().map(|e| json!({"unix_ms":e.unix_ms,"module":e.module.map(|m|m.short_name()),"level":format!("{:?}",e.level),"text":e.text})).collect::<Vec<_>>()))
            }
            "list_processes" => {
                let processes = crate::process_target::list_processes();
                let offset = args["offset"].as_u64().unwrap_or(0) as usize;
                let limit = args["limit"].as_u64().unwrap_or(50) as usize;
                Ok(
                    json!({"total":processes.len(),"processes":processes.iter().skip(offset).take(limit).map(|p|json!({"pid":p.pid,"name":p.name,"window_title":p.window_title,"socket_count":p.sockets.len()})).collect::<Vec<_>>()}),
                )
            }
            "get_process_sockets" => {
                let pid = args["pid"].as_u64().unwrap() as u32;
                let sockets = crate::process_target::get_sockets_for_pid(pid);
                let offset = args["offset"].as_u64().unwrap_or(0) as usize;
                Ok(
                    json!({"pid":pid,"total":sockets.len(),"sockets":sockets.iter().skip(offset).take(100).collect::<Vec<_>>()}),
                )
            }
            "validate_filter" | "set_filter" => {
                if name == "set_filter" && running {
                    return Err("Stop filtering before changing the filter".into());
                }
                let filter = args["filter"].as_str().unwrap();
                self.lib
                    .as_ref()
                    .ok_or("WinDivert.dll is not available")?
                    .compile_filter(filter)?;
                if name == "set_filter" {
                    self.detach_target();
                    self.config.filter = filter.into();
                    self.preset_selected = usize::MAX;
                    self.mark_dirty();
                }
                Ok(json!({"valid":true,"filter":filter}))
            }
            "set_target" => {
                if running {
                    return Err("Stop filtering before selecting a process".into());
                }
                let pid =
                    u32::try_from(args["pid"].as_u64().unwrap()).map_err(|_| "PID out of range")?;
                let process = crate::process_target::list_processes()
                    .into_iter()
                    .find(|p| p.pid == pid)
                    .ok_or("Process not found")?;
                if process.sockets.is_empty() {
                    return Err("Target has no active sockets".into());
                }
                self.target_pid = Some(pid);
                self.target_process_name = Some(process.name);
                self.target_window_title = process.window_title;
                self.target_filter_tcp = true;
                self.target_filter_udp = true;
                self.target_filter_inbound = true;
                self.target_filter_outbound = true;
                self.update_target_filter(false);
                self.preset_selected = usize::MAX;
                Ok(json!({"pid":pid,"filter":self.config.filter}))
            }
            "configure_module" => {
                let kind = ModuleKind::from_short_name(args["module"].as_str().unwrap()).unwrap();
                let p = &self.params[kind.index()];
                for key in args.as_object().unwrap().keys() {
                    let relevant = match key.as_str() {
                        "delay_ms" => kind == ModuleKind::Lag,
                        "throttle_frame_ms" | "drop_throttled" => kind == ModuleKind::Throttle,
                        "dup_count" => kind == ModuleKind::Duplicate,
                        "redo_checksum" => kind == ModuleKind::Tamper,
                        "bandwidth_limit_kbps" => kind == ModuleKind::Bandwidth,
                        _ => true,
                    };
                    if !relevant {
                        return Err(format!("{key} does not apply to {}", kind.short_name()));
                    }
                }
                for (key, value) in args.as_object().unwrap() {
                    match key.as_str() {
                        "enabled" => p.enabled.store(value.as_bool().unwrap(), Ordering::Relaxed),
                        "inbound" => p
                            .direction
                            .inbound
                            .store(value.as_bool().unwrap(), Ordering::Relaxed),
                        "outbound" => p
                            .direction
                            .outbound
                            .store(value.as_bool().unwrap(), Ordering::Relaxed),
                        "chance_percent" => p.set_chance_percent(value.as_f64().unwrap() as f32),
                        "delay_ms" => p
                            .delay_ms
                            .store(value.as_i64().unwrap() as i32, Ordering::Relaxed),
                        "throttle_frame_ms" => p
                            .throttle_frame_ms
                            .store(value.as_i64().unwrap() as i32, Ordering::Relaxed),
                        "drop_throttled" => p
                            .drop_throttled
                            .store(value.as_bool().unwrap(), Ordering::Relaxed),
                        "dup_count" => p
                            .dup_count
                            .store(value.as_i64().unwrap() as i32, Ordering::Relaxed),
                        "redo_checksum" => p
                            .redo_checksum
                            .store(value.as_bool().unwrap(), Ordering::Relaxed),
                        "bandwidth_limit_kbps" => p
                            .bandwidth_limit_kbps
                            .store(value.as_i64().unwrap() as i32, Ordering::Relaxed),
                        _ => (),
                    }
                }
                self.mark_dirty();
                self.mcp_tool("get_status", &json!({}))
            }
            "start" => {
                if running {
                    return Err("Filtering is already running".into());
                }
                if self.target_pid.is_some() {
                    self.update_target_filter(false);
                }
                let deadline = Instant::now() + Duration::from_secs(args["duration_secs"].as_u64().unwrap());
                self.start_filtering_until(deadline);
                if self.engine.is_none() {
                    return Err(self.status.clone());
                }
                self.mcp_started = true;
                self.mcp_tool("get_status", &json!({}))
            }
            "stop" => {
                self.stop_filtering();
                self.mcp_tool("get_stats", &json!({}))
            }
            "reset_next" => {
                let p = &self.params[ModuleKind::Reset.index()];
                if !running || !p.enabled.load(Ordering::Relaxed) {
                    return Err("Start filtering and enable the reset module first".into());
                }
                p.rst_next.fetch_add(1, Ordering::Relaxed);
                Ok(json!({"queued":true}))
            }
            _ => Err("Unknown tool".into()),
        }
    }
}
