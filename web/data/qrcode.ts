function arrayBufferToBase64(buffer) {
  var binary = "";
  var bytes = [].slice.call(new Uint8Array(buffer));

  bytes.forEach((b) => (binary += String.fromCharCode(b)));

  return window.btoa(binary);
}

export const qrcodeImageFromResponse = (response: any): Promise<string> => {
  if (!response) {
    return Promise.resolve("");
  }
  return response.arrayBuffer().then((buffer) => {
    var imageStr = arrayBufferToBase64(buffer);

    return `data:image/png;base64,${imageStr}`;
  });
};
