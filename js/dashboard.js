let queue = Promise.resolve();
// Handle events one at a time so detection never races itself.


/*
--------------------------------------------------
EVENT DISPLAY SETTINGS
--------------------------------------------------
*/

const INITIAL_EVENTS = 5;
const EVENTS_STEP = 10;

// Current event filter.
// ALL = show everything.
let eventFilter = "ALL";


// Number of events currently displayed.
let eventLimit = INITIAL_EVENTS;


/*
--------------------------------------------------
COUNT ROWS
--------------------------------------------------
*/

async function countRows(table, filter) {

  let q = sb
    .from(table)
    .select("*", {
      count: "exact",
      head: true
    });

  if (filter) {
    q = filter(q);
  }

  const {
    count,
    error
  } = await q;

  if (error) {
    throw error;
  }

  return count;
}


/*
--------------------------------------------------
FETCH EVENTS
--------------------------------------------------
*/

async function fetchEvents() {

  let q = sb
    .from("security_events")
    .select("*")
    .order("created_at", {
      ascending: false
    })
    .limit(eventLimit);


  // Apply selected event type.
  if (eventFilter !== "ALL") {

    q = q.eq(
      "event_type",
      eventFilter
    );

  }


  const {
    data,
    error
  } = await q;


  if (error) {
    throw error;
  }

  return data;
}


/*
--------------------------------------------------
FETCH ACTIVE ALERTS
--------------------------------------------------
*/

async function fetchActiveAlerts() {

  const {
    data,
    error
  } = await sb
    .from("security_alerts")
    .select("*")
    .in(
      "status",
      [
        "OPEN",
        "ACKNOWLEDGED"
      ]
    )
    .order(
      "created_at",
      {
        ascending: false
      }
    )
    .limit(5);


  if (error) {
    throw error;
  }

  return data;
}


/*
--------------------------------------------------
UPDATE FILTER MESSAGE
--------------------------------------------------
*/

function updateActivityFilter() {

  const filterBox =
    document.getElementById(
      "activity-filter"
    );


  if (eventFilter !== "ALL") {

    filterBox.textContent =
      "Showing " +
      eventFilter +
      " events";

    filterBox.classList.remove(
      "hidden"
    );

  } else {

    filterBox.textContent = "";

    filterBox.classList.add(
      "hidden"
    );

  }

}


/*
--------------------------------------------------
CHECK SHOW MORE BUTTON
--------------------------------------------------
*/

async function updateShowMoreButton() {

  const showMore =
    document.getElementById(
      "show-more-events"
    );


  try {

    let total;


    if (eventFilter === "ALL") {

      total =
        await countRows(
          "security_events"
        );

    } else {

      total =
        await countRows(
          "security_events",
          q =>
            q.eq(
              "event_type",
              eventFilter
            )
        );

    }


    if (total > eventLimit) {

      showMore.style.display =
        "inline-block";

    } else {

      showMore.style.display =
        "none";

    }

  } catch (error) {

    console.error(
      "Could not determine event count:",
      error
    );

    showMore.style.display =
      "none";

  }

}


/*
--------------------------------------------------
RENDER EVENTS
--------------------------------------------------
*/

function renderEvents(events) {

  const tbody =
    document.getElementById(
      "events"
    );


  if (!events.length) {

    tbody.innerHTML =
      '<tr>' +
      '<td colspan="5" class="empty">' +
      'No security events found.' +
      '</td>' +
      '</tr>';

  } else {

    tbody.innerHTML =
      events.map(e =>

        `<tr>
          <td class="m">
            ${esc(e.event_type)}
          </td>

          <td>
            ${badge(e.severity)}
          </td>

          <td class="m">
            ${esc(e.target)}
          </td>

          <td class="m">
            ${esc(e.source)}
          </td>

          <td>
            ${fmt(e.created_at)}
          </td>
        </tr>`

      ).join("");

  }


  updateShowMoreButton();

}


/*
--------------------------------------------------
REFRESH ONLY EVENTS
--------------------------------------------------
*/

async function refreshEvents() {

  const events =
    await fetchEvents();

  renderEvents(events);

  updateActivityFilter();

}


/*
--------------------------------------------------
FULL DASHBOARD REFRESH
--------------------------------------------------
*/

async function refresh() {

  try {

    const [
      events,
      alerts,
      total,
      failed,
      active,
      openInc
    ] = await Promise.all([

      fetchEvents(),

      fetchActiveAlerts(),

      countRows(
        "security_events"
      ),

      countRows(
        "security_events",
        q =>
          q.eq(
            "event_type",
            "FAILED_LOGIN"
          )
      ),

      countRows(
        "security_alerts",
        q =>
          q.in(
            "status",
            [
              "OPEN",
              "ACKNOWLEDGED"
            ]
          )
      ),

      countRows(
        "security_incidents",
        q =>
          q.neq(
            "status",
            "RESOLVED"
          )
      )

    ]);


    /*
    ----------------------------------------------
    UPDATE STAT CARDS
    ----------------------------------------------
    */

    document.getElementById(
      "s-total"
    ).textContent = total;


    document.getElementById(
      "s-failed"
    ).textContent = failed;


    document.getElementById(
      "s-alerts"
    ).textContent = active;


    document.getElementById(
      "s-inc"
    ).textContent = openInc;


    /*
    ----------------------------------------------
    EVENTS
    ----------------------------------------------
    */

    renderEvents(events);

    updateActivityFilter();


    /*
    ----------------------------------------------
    ACTIVE ALERTS
    ----------------------------------------------
    */

    document.getElementById(
      "alerts"
    ).innerHTML = alerts.length

      ? alerts.map(a =>

          `<div class="card alertbox">

            <b>
              🚨 ${esc(a.title)}
            </b>

            ${badge(a.severity)}

            ${badge(a.status)}

            <div
              class="sub"
              style="margin:4px 0 0"
            >

              Source
              ${esc(a.source)}

              ·
              ${a.event_count}
              events

              ·

              <a href="alerts.html">
                open alert
              </a>

            </div>

          </div>`

        ).join("")

      : '<div class="empty">' +
        'No active alerts.' +
        '</div>';


  } catch (e) {

    console.error(e);

    toast(
      "Could not load data. Please try again.",
      "error"
    );

  }

}


/*
--------------------------------------------------
NOTIFICATIONS
--------------------------------------------------
*/

function notify(created) {

  created.forEach(a =>

    toast(
      "🚨 " + a.title,
      "alert"
    )

  );

}


/*
--------------------------------------------------
SHOW ALL EVENTS
--------------------------------------------------
*/

function showAllEvents() {

  eventFilter = "ALL";

  eventLimit =
    INITIAL_EVENTS;


  document.getElementById(
    "event-type-filter"
  ).value = "ALL";


  updateActivityFilter();

  refreshEvents();


  document.getElementById(
    "recent-activity"
  ).scrollIntoView({

    behavior: "smooth",

    block: "start"

  });

}


/*
--------------------------------------------------
SHOW FAILED LOGINS
--------------------------------------------------
*/

function showFailedLogins() {

  eventFilter =
    "FAILED_LOGIN";

  eventLimit =
    INITIAL_EVENTS;


  document.getElementById(
    "event-type-filter"
  ).value =
    "FAILED_LOGIN";


  updateActivityFilter();

  refreshEvents();


  document.getElementById(
    "recent-activity"
  ).scrollIntoView({

    behavior: "smooth",

    block: "start"

  });

}


/*
--------------------------------------------------
EVENT TYPE DROPDOWN
--------------------------------------------------
*/

function setupEventFilter() {

  const filter =
    document.getElementById(
      "event-type-filter"
    );


  filter.addEventListener(
    "change",
    async e => {

      eventFilter =
        e.target.value;

      eventLimit =
        INITIAL_EVENTS;


      try {

        await refreshEvents();

      } catch (error) {

        console.error(error);

        toast(
          "Could not filter events.",
          "error"
        );

      }

    }
  );

}


/*
--------------------------------------------------
DASHBOARD CARD ACTIONS
--------------------------------------------------
*/

function setupDashboardActions() {


  /*
  TOTAL EVENTS
  */

  document.getElementById(
    "total-card"
  ).addEventListener(
    "click",
    showAllEvents
  );


  /*
  FAILED LOGINS
  */

  document.getElementById(
    "failed-card"
  ).addEventListener(
    "click",
    showFailedLogins
  );


  /*
  ACTIVE ALERTS
  */

  document.getElementById(
    "alerts-card"
  ).addEventListener(
    "click",
    () => {

      window.location.href =
        "alerts.html";

    }
  );


  /*
  OPEN INCIDENTS
  */

  document.getElementById(
    "incidents-card"
  ).addEventListener(
    "click",
    () => {

      window.location.href =
        "incidents.html";

    }
  );


  /*
  KEYBOARD SUPPORT
  */

  document.getElementById(
    "total-card"
  ).addEventListener(
    "keydown",
    e => {

      if (
        e.key === "Enter" ||
        e.key === " "
      ) {

        e.preventDefault();

        showAllEvents();

      }

    }
  );


  document.getElementById(
    "failed-card"
  ).addEventListener(
    "keydown",
    e => {

      if (
        e.key === "Enter" ||
        e.key === " "
      ) {

        e.preventDefault();

        showFailedLogins();

      }

    }
  );


  document.getElementById(
    "alerts-card"
  ).addEventListener(
    "keydown",
    e => {

      if (
        e.key === "Enter" ||
        e.key === " "
      ) {

        e.preventDefault();

        window.location.href =
          "alerts.html";

      }

    }
  );


  document.getElementById(
    "incidents-card"
  ).addEventListener(
    "keydown",
    e => {

      if (
        e.key === "Enter" ||
        e.key === " "
      ) {

        e.preventDefault();

        window.location.href =
          "incidents.html";

      }

    }
  );


  /*
  SHOW MORE EVENTS
  */

  document.getElementById(
    "show-more-events"
  ).addEventListener(
    "click",
    async () => {

      eventLimit +=
        EVENTS_STEP;


      try {

        await refreshEvents();

      } catch (e) {

        console.error(e);

        toast(
          "Could not load more events.",
          "error"
        );

      }

    }
  );

}


/*
--------------------------------------------------
REALTIME EVENT HANDLER
--------------------------------------------------
*/

function handleNewEvent(ev) {

  queue = queue
    .then(async () => {

      notify(
        await analyseEvent(ev)
      );

      await refresh();

    })
    .catch(e => {

      console.error(e);

      toast(
        "Detection error. Please refresh.",
        "error"
      );

    });

}


/*
--------------------------------------------------
CATCH-UP SCAN
--------------------------------------------------
*/

async function catchUpScan() {

  const since =
    new Date(
      Date.now() -
      5 * 60000
    ).toISOString();


  const {
    data,
    error
  } = await sb
    .from("security_events")
    .select("source")
    .eq(
      "event_type",
      "FAILED_LOGIN"
    )
    .gte(
      "created_at",
      since
    );


  if (error) {
    throw error;
  }


  for (
    const s of
    new Set(
      data.map(
        r => r.source
      )
    )
  ) {

    notify(
      await analyseSource(s)
    );

  }

}


/*
--------------------------------------------------
REALTIME CONNECTION
--------------------------------------------------
*/

function startRealtime() {

  const st =
    document.getElementById(
      "status"
    );


  sb.channel(
    "soc-events"
  )

    .on(

      "postgres_changes",

      {
        event: "INSERT",
        schema: "public",
        table: "security_events"
      },

      p =>
        handleNewEvent(
          p.new
        )

    )

    .subscribe(s => {

      const ok =
        s === "SUBSCRIBED";


      st.textContent =
        ok
          ? "● ONLINE"
          : "● CONNECTING...";


      st.className =
        "status" +
        (
          ok
            ? ""
            : " off"
        );

    });

}


/*
--------------------------------------------------
START DASHBOARD
--------------------------------------------------
*/

(async () => {

  if (
    !(await requireAnalyst())
  ) {

    return;

  }


  setupEventFilter();

  setupDashboardActions();


  await refresh();


  try {

    await catchUpScan();

    await refresh();

  } catch (e) {

    console.error(e);

  }


  startRealtime();

})();