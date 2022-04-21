const source_code_textarea = document.querySelector('[name="source"]');
const dist_code_textarea = document.querySelector('[name="dist"]');
const convert_button = document.querySelector(".convert_button");

convert_button.addEventListener("click", async () => {
  const res = await fetch("/api/obfuscate", {
    method: 'POST',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({value: source_code_textarea.value.trim()})
  });

  if (res.ok) {
    const json = await res.json();
    dist_code_textarea.value = json.value
  } else {
    alert("The error has occured: " + response.status);
  }
});

try {
  const confirm_button = document.querySelector(".confirm_button")
  const confirm_message = document.querySelector(".confirm_message")

  confirm_button.addEventListener("click", async () => {
    const res = await fetch("/confirmation/jwt", {
      method: 'PUT',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      }
    });

    if (res.ok) {
      confirm_message.textContent = "We sended you an email"
      confirm_button.textContent = "Send again"
    }
  })
} catch(error) {
  console.error(error)
}