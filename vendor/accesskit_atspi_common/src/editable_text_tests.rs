use std::sync::{Arc, Mutex};

use accesskit::{Action, ActionData, ActionRequest, Node, NodeId, Role, TreeId, TreeUpdate};
use accesskit_consumer::Tree;
use atspi_common::{Interface, State};

use crate::{ActionHandlerNoMut, AppContext, PlatformNode, WindowBounds, context::Context};

struct Capture(Arc<Mutex<Vec<ActionRequest>>>);

impl ActionHandlerNoMut for Capture {
    fn do_action(&self, request: ActionRequest) {
        self.0.lock().unwrap().push(request);
    }
}

fn input() -> Node {
    let mut node = Node::new(Role::MultilineTextInput);
    node.set_children([NodeId(3)]);
    node.add_action(Action::SetValue);
    node.add_action(Action::EditText);
    node
}

fn fixture(input: Node) -> (Arc<Context>, PlatformNode, Arc<Mutex<Vec<ActionRequest>>>) {
    let mut root = Node::new(Role::Window);
    root.set_children([NodeId(2)]);
    let mut run = Node::new(Role::TextRun);
    let text = "Troy 🦀\nGreendale";
    run.set_value(text);
    run.set_character_lengths(
        text.chars()
            .map(|ch| ch.len_utf8() as u8)
            .collect::<Vec<_>>(),
    );
    let tree = Tree::new(
        TreeUpdate {
            nodes: vec![(NodeId(1), root), (NodeId(2), input), (NodeId(3), run)],
            tree: Some(accesskit::Tree::new(NodeId(1))),
            tree_id: TreeId::ROOT,
            focus: NodeId(2),
        },
        true,
    );
    let id = tree
        .state()
        .node_by_tree_local_id(NodeId(2), TreeId::ROOT)
        .unwrap()
        .id();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let context = Context::new(
        &AppContext::new(None),
        tree,
        Arc::new(Capture(requests.clone())),
        WindowBounds::default(),
    );
    let node = PlatformNode::new(&context, 0, id);
    (context, node, requests)
}

#[test]
fn editable_interface_and_requests_follow_live_permissions() {
    for (readonly, disabled) in [(false, false), (true, false), (false, true)] {
        let mut input = input();
        if readonly {
            input.set_read_only();
        }
        if disabled {
            input.set_disabled();
        }
        let (_context, node, requests) = fixture(input);
        assert_eq!(
            node.interfaces().unwrap().contains(Interface::EditableText),
            !readonly && !disabled
        );
        assert_eq!(
            node.set_text_contents("Greendale").unwrap(),
            !readonly && !disabled
        );
        assert_eq!(
            node.insert_text(0, "Troy", 4).unwrap(),
            !readonly && !disabled
        );
        assert_eq!(node.delete_text(0, 4).unwrap(), !readonly && !disabled);
        assert_eq!(node.cut_text(0, 4).unwrap(), !readonly && !disabled);
        assert_eq!(node.paste_text(0).unwrap(), !readonly && !disabled);
        assert_eq!(node.copy_text(0, 4).unwrap(), !disabled);
        if disabled {
            assert!(requests.lock().unwrap().is_empty());
        }
    }
}

#[test]
fn enabled_and_sensitive_states_follow_disabled_controls() {
    for role in [Role::Button, Role::CheckBox, Role::MultilineTextInput] {
        for disabled in [false, true] {
            let mut control = Node::new(role);
            control.set_children([NodeId(3)]);
            if disabled {
                control.set_disabled();
            }
            let (_context, node, _) = fixture(control);
            let states = node.state();
            assert_eq!(states.contains(State::Enabled), !disabled, "{role:?}");
            assert_eq!(states.contains(State::Sensitive), !disabled, "{role:?}");
        }
    }
    let mut control = input();
    control.set_read_only();
    let (_context, node, _) = fixture(control);
    let states = node.state();
    assert!(states.contains(State::ReadOnly));
    assert!(states.contains(State::Enabled));
    assert!(states.contains(State::Sensitive));
    assert!(!node.interfaces().unwrap().contains(Interface::EditableText));
}

#[test]
fn unicode_positions_and_byte_lengths_produce_one_atomic_edit() {
    let (_context, node, requests) = fixture(input());
    assert!(node.insert_text(6, "é🦀tail", 6).unwrap());
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.action, Action::EditText);
    assert_eq!(request.target_node, NodeId(2));
    assert_eq!(request.target_tree, TreeId::ROOT);
    let Some(ActionData::ReplaceText { selection, value }) = &request.data else {
        panic!("expected a range edit");
    };
    assert_eq!(selection.anchor, selection.focus);
    assert_eq!(selection.focus.node, NodeId(3));
    assert_eq!(selection.focus.character_index, 6);
    assert_eq!(value.as_ref(), "é🦀");
}

#[test]
fn invalid_ranges_and_split_utf8_are_rejected_without_actions() {
    let (_context, node, requests) = fixture(input());
    assert!(node.insert_text(-1, "Troy", 4).is_err());
    assert!(node.insert_text(999, "Troy", 4).is_err());
    assert!(node.insert_text(0, "Troy", -1).is_err());
    assert!(!node.insert_text(0, "🦀", 1).unwrap());
    assert!(node.delete_text(5, 4).is_err());
    assert!(node.copy_text(-1, 4).is_err());
    assert!(node.cut_text(0, 999).is_err());
    assert!(node.paste_text(999).is_err());
    assert!(requests.lock().unwrap().is_empty());
}

#[test]
fn clipboard_ranges_and_full_replacement_preserve_the_requested_operation() {
    let (_context, node, requests) = fixture(input());
    assert!(node.copy_text(5, 6).unwrap());
    assert!(node.cut_text(5, 6).unwrap());
    assert!(node.paste_text(6).unwrap());
    assert!(node.delete_text(5, 6).unwrap());
    assert!(node.set_text_contents("Greendale 🦀\nTroy").unwrap());
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 5);
    let Some(ActionData::CopyText(copy)) = requests[0].data else {
        panic!("expected copy");
    };
    assert_eq!(
        (copy.anchor.character_index, copy.focus.character_index),
        (5, 6)
    );
    assert!(matches!(requests[1].data, Some(ActionData::CutText(range)) if range == copy));
    assert!(
        matches!(requests[2].data, Some(ActionData::PasteText(position)) if position == copy.focus)
    );
    assert!(
        matches!(&requests[3].data, Some(ActionData::ReplaceText { selection, value }) if selection == &copy && value.is_empty())
    );
    assert_eq!(requests[4].action, Action::SetValue);
    assert_eq!(
        requests[4].data,
        Some(ActionData::Value("Greendale 🦀\nTroy".into()))
    );
}
