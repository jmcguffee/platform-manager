# One "who's on call" answer for a schedule, as shift rows.
#
# Input: a Pup envelope for GET /api/v2/on-call/schedules/{id}/responders with
# include=responders.shifts.user: {data, included: [schedule_oncall_responder, shifts, users]}.
# Args: $schedule (name), $sid (schedule ID).

(.included // []) as $inc
| ($inc | map(select(.type == "users")) | map({key: .id, value: (.attributes // {})}) | from_entries) as $users
| ($inc | map(select(.type == "schedule_oncall_responder"))
        | map({position: (.attributes.position // ""), shifts: [.relationships.shifts.data[]?.id]})) as $responders
| $inc[] | select(.type == "shifts") | . as $s
| (.relationships.user.data.id // "") as $uid
| {kind: "shift", schedule: $schedule, schedule_id: $sid,
   start: (.attributes.start // null), end: (.attributes.end // null),
   position: ([$responders[] | select(.shifts | index($s.id)) | .position] | first // ""),
   user_id: $uid, name: ($users[$uid].name // $users[$uid].handle // "Unknown user"),
   email: ($users[$uid].email // "")}
