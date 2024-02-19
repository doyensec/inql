// Decode data passed in fragment and URL params
async function getInqlParams() {
  const urlParams = Object.fromEntries(new URLSearchParams(window.location.search));
  const target = decodeURIComponent(urlParams.target || "");
  const session = decodeURIComponent(urlParams.session || "");

  const params = {
      target: target,
      session: session,
      query: "",
      variables: "{}"
  }
  if (!window.location.hash) {
      return params
  }

  try {
      let data = window.location.hash.split(":")[1];
      data = data.replace(/_/g, '/').replace(/-/g, '+').replace(/=/g, ''); // URL-safe base64 to standard base64
      let decoded = Uint8Array.from(atob(data), c => c.charCodeAt(0));
      let ds = new DecompressionStream("gzip");
      let blob = new Blob([decoded.buffer]);
      const stream = blob.stream().pipeThrough(ds);
      const decompressedString = await new Response(stream).text();
      return {...params, ...JSON.parse(decompressedString)};
  } catch (error) {
      console.log("Failed parsing data sent in fragment.")
      console.log(error)
      return params;
  }
}

export const inql = await getInqlParams();