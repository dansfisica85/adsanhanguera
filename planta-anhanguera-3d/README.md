# Campus 3D — Anhanguera Sertãozinho

Aplicação web 3D responsiva para explorar os ambientes da Faculdade Anhanguera de Sertãozinho e, mediante autorização do visitante, iniciar uma rota visual a partir da Entrada Principal.

## O que foi implementado

- 42 ambientes no térreo e 5 no mezanino, com nome, número/código, categoria e descrição;
- mobiliário procedural por tipo de ambiente: carteiras, computadores, bancadas, estantes, mesas, cadeiras, balcões, armários, louças e plantas;
- estacionamento, jardins, vegetação, calçada e portal da entrada;
- visualização em maquete, vista superior e caminhada em primeira pessoa;
- controles por teclado, mouse, toque e controle direcional para celular;
- colisão básica com as paredes no modo caminhar;
- busca e foco automático em qualquer ambiente;
- minimapa com posição, destino e rota;
- rota 3D animada entre a Entrada Principal e o destino;
- geofence de 180 m para habilitar a rota real somente dentro do campus;
- simulação pela entrada para testar a rota fora do campus;
- camadas de paredes, nomes, mobília, mezanino, rota e planta-base;
- importação/exportação do layout JSON e exportação do modelo GLB.

## Executar localmente

Requer Node.js 20.19+ ou 22.12+.

```bash
npm install
npm run dev
```

Abra o endereço mostrado pelo Vite. Para validar antes da publicação:

```bash
npm run check
npm test
npm run build
npm run preview
```

## Geolocalização e privacidade

O navegador só solicita a posição quando o visitante toca em **Usar minha localização**. Se a permissão já estiver concedida, a verificação pode ocorrer automaticamente. A latitude e a longitude são processadas em memória no próprio dispositivo; não há API, banco de dados, analytics ou envio da posição para terceiros.

A geolocalização comum de celulares e notebooks não oferece localização interna precisa, especialmente dentro de prédios. Por isso, ela confirma apenas se o visitante está no perímetro aproximado do campus. A rota começa na **Entrada Principal**. Para localizar a pessoa dentro do prédio com precisão seria necessário instalar infraestrutura adicional, como beacons Bluetooth, Wi-Fi RTT ou QR codes de recalibração.

A API de geolocalização exige HTTPS em produção (localhost é aceito durante o desenvolvimento).

## Fontes e precisão

A geometria foi reconstruída visualmente a partir do croqui atualizado, da maquete 3D e da planta técnica presentes no pacote. Nomes, setores e mobiliário seguem as imagens de referência, mas dimensões, espessuras, portas, orientação geográfica e percursos continuam aproximados.

Este projeto serve para orientação e visualização. Não é planta executiva, laudo, sistema de localização de emergência nem rota oficial de fuga. Antes do uso institucional, valide o modelo com levantamento arquitetônico cotado, responsáveis da unidade, acessibilidade e segurança do trabalho.

## Estrutura principal

- `index.html`: interface e acessibilidade;
- `style.css`: layout responsivo para computador e celular;
- `main.js`: cena, câmera, mobília, navegação, minimapa e rotas;
- `src/layout.js`: ambientes, categorias, descrições e geofence;
- `src/geolocation.js`: cálculo de distância e verificação do perímetro;
- `tests/geolocation.test.mjs`: verificações do geofence;
- `assets/`: referências e modelos preservados.
