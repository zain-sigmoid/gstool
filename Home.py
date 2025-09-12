import streamlit as st
from pillars import cards_data

# Set the page configuration
# The layout="wide" option allows the content to occupy the full width of the screen.
st.set_page_config(
    page_title="Code Quality and Security Dashboard",
    layout="wide",
)

st.title("🏛️ Code Quality and Security Dashboard")
st.markdown(
    "Click on a card to navigate to the respective page and learn more about each quality pillar."
)


# --- Display Cards in a Grid ---
# Create a 2x2 grid for the cards
col1, col2, col3 = st.columns(3)
columns = [col1, col2, col3]

for i, card in enumerate(cards_data):
    # Place each card in its designated column
    with columns[i % 3]:
        # st.page_link makes the content within it a clickable link to another page
        with st.container(border=True, height=200):
            # st.markdown(
            #     "<div><h2 style='font-size: 2rem;'>{f"{card['icon']} {card['title']}"]}</div>", unsafe_allow_html=True
            # )
            # st.markdown(card["text"])
            st.markdown(
                f"""
                <div style="display:flex; flex-direction:column; justify-content:space-between; margin-bottom:10px;">
                    <h2 style="font-size:1.2rem; margin:0;">{card['icon']} {card['title']}</h2>
                    <div style="margin-top:6px;">{card['text']}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            st.page_link(
                card["page"],
                label="Open →",
            )
