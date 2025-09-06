export const echo = async (event) => {
  return {
    statusCode: 200,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      receivedAuthorization: event.headers?.authorization || event.headers?.Authorization || null,
      allHeaders: event.headers
    })
  };
};