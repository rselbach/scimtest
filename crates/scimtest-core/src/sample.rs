use std::collections::{BTreeMap, HashMap};

use crate::{Error, model::*, store::new_id};

pub(crate) fn append(directory: &mut Directory) -> Result<SeedResult, Error> {
    let samples = [
        (
            "Troy",
            "Barnes",
            "tbarnes",
            "troy.barnes",
            true,
            "GC-1001",
            "Air Conditioning Repair",
            "Facilities",
            "3100",
            "dpelton",
            "student",
        ),
        (
            "Abed",
            "Nadir",
            "anadir",
            "abed.nadir",
            true,
            "GC-1002",
            "Film Studies",
            "Academics",
            "2100",
            "jwinger",
            "student",
        ),
        (
            "Annie",
            "Edison",
            "aedison",
            "annie.edison",
            true,
            "GC-1003",
            "Criminology",
            "Academics",
            "2200",
            "jwinger",
            "student",
        ),
        (
            "Britta",
            "Perry",
            "bperry",
            "britta.perry",
            true,
            "GC-1004",
            "Psychology",
            "Academics",
            "2300",
            "jwinger",
            "student",
        ),
        (
            "Shirley",
            "Bennett",
            "sbennett",
            "shirley.bennett",
            true,
            "GC-1005",
            "Business",
            "Academics",
            "2400",
            "jwinger",
            "student",
        ),
        (
            "Jeff",
            "Winger",
            "jwinger",
            "jeff.winger",
            true,
            "GC-1006",
            "Law",
            "Academics",
            "2500",
            "dpelton",
            "faculty",
        ),
        (
            "Dean",
            "Pelton",
            "dpelton",
            "dean.pelton",
            true,
            "GC-0001",
            "Office of the Dean",
            "Administration",
            "1000",
            "",
            "admin",
        ),
        (
            "Señor",
            "Chang",
            "schang",
            "senor.chang",
            false,
            "GC-0666",
            "Spanish",
            "Academics",
            "2600",
            "dpelton",
            "faculty",
        ),
        (
            "Leonard",
            "Rodriguez",
            "lrodriguez",
            "leonard.rodriguez",
            true,
            "GC-1007",
            "Continuing Education",
            "Academics",
            "2700",
            "dpelton",
            "student",
        ),
        (
            "Magnitude",
            "PopPop",
            "magnitude",
            "magnitude",
            true,
            "GC-1008",
            "Air Conditioning Repair",
            "Facilities",
            "3100",
            "tbarnes",
            "student",
        ),
    ];
    let mut ids = directory
        .users
        .iter()
        .map(|user| {
            (
                crate::casefold::lowercase(&user.fields.username),
                user.id.clone(),
            )
        })
        .collect::<HashMap<_, _>>();
    let mut emails = directory
        .users
        .iter()
        .map(|user| crate::casefold::lowercase(&user.fields.email))
        .collect::<std::collections::HashSet<_>>();
    let mut managers = Vec::new();
    for (
        given,
        family,
        username,
        email,
        active,
        employee,
        department,
        division,
        cost_center,
        manager,
        role,
    ) in samples
    {
        let email = format!("{email}@greendale.edu");
        if ids.contains_key(username) || emails.contains(&crate::casefold::lowercase(&email)) {
            continue;
        }
        let id = new_id("user");
        ids.insert(username.to_owned(), id.clone());
        emails.insert(crate::casefold::lowercase(&email));
        managers.push((directory.users.len(), manager));
        directory.users.push(User {
            id,
            fields: UserInput {
                given_name: given.into(),
                family_name: family.into(),
                username: username.into(),
                email,
                active,
                employee_number: employee.into(),
                department: department.into(),
                division: division.into(),
                cost_center: cost_center.into(),
                organization: "Greendale Community College".into(),
                attributes: BTreeMap::from([("role".into(), role.into())]),
                ..Default::default()
            },
            dirty: true,
            ..Default::default()
        });
    }
    let users_added = managers.len();
    for (index, manager) in managers {
        directory.users[index].fields.manager_id = ids.get(manager).cloned().unwrap_or_default();
    }
    let groups = [
        (
            "Study Group",
            vec![
                "tbarnes", "anadir", "aedison", "bperry", "sbennett", "jwinger",
            ],
        ),
        ("Faculty", vec!["dpelton", "schang"]),
        (
            "Air Conditioning Repair Annex",
            vec!["tbarnes", "magnitude"],
        ),
    ];
    let mut groups_added = 0;
    for (name, members) in groups {
        if directory.groups.iter().any(|group| {
            crate::casefold::lowercase(&group.fields.display_name)
                == crate::casefold::lowercase(name)
        }) {
            continue;
        }
        directory.groups.push(Group {
            id: new_id("group"),
            fields: GroupInput {
                display_name: name.into(),
                member_ids: members
                    .iter()
                    .filter_map(|username| ids.get(*username).cloned())
                    .collect(),
            },
            dirty: true,
            ..Default::default()
        });
        groups_added += 1;
    }
    Ok(SeedResult {
        users_added,
        groups_added,
    })
}
